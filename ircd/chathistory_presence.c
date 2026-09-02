/*
 * IRC - Internet Relay Chat, ircd/chathistory_presence.c
 * Copyright (C) 2026 Nefarious Development Team
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
 */
/** @file
 * @brief Per-anchor channel presence tracking.  See header for the
 * design narrative; the data shape and FIFO-drop semantics are
 * documented inline below.
 */
#include "config.h"

#include "chathistory_presence.h"

#include "channel.h"
#include "client.h"
#include "crdt_hlc.h"
#include "hash.h"
#include "history.h"
#include "db_cursor.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_types.h"
#include "history.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "metadata.h"
#include "msg.h"
#include "send.h"
#include "s_debug.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "s_debug.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/** Hard structural cap on closed intervals per (anchor, channel)
 * record.  Sized to provide reasonable headroom for the runtime
 * feature FEAT_CHATHISTORY_PRESENCE_MAX_INTERVALS to be tuned within
 * (default 64, max = this value).  Each record persists bytewise to
 * the store, so changing this is a schema-version bump — old-sized
 * records get treated as missing by acct_load's size check and are
 * rebuilt from fresh JOIN/PART events.  At 256 intervals, one
 * (anchor, channel) record is ~4KB; a server with 10k users in 50
 * channels each maxing out their intervals tops out around 2GB
 * presence footprint, well within MDBX/RocksDB working set. */
#define PRESENCE_MAX_INTERVALS 256

/** Hard ceiling on effective_max_intervals(): must stay <= 255 because
 * presence_record.count is uint8_t and record_apply_part() does count++ right
 * after writing intervals[count]; a cap of 256 lets count overflow 255->0 and
 * orphan every earlier interval.  PRESENCE_MAX_INTERVALS (the array dimension)
 * stays 256 for headroom; only the count-driving cap is held back. */
#define PRESENCE_MAX_INTERVALS_SAFE (PRESENCE_MAX_INTERVALS - 1)

/** Effective per-record cap clamped to the structural limit.  Reading
 * the feature on each insert is cheap (single int lookup) and avoids
 * needing a rehash-time notification handler. */
static unsigned int effective_max_intervals(void)
{
  int v = feature_int(FEAT_CHATHISTORY_PRESENCE_MAX_INTERVALS);
  if (v <= 0)
    return PRESENCE_MAX_INTERVALS_SAFE;
  if (v > PRESENCE_MAX_INTERVALS_SAFE)
    return PRESENCE_MAX_INTERVALS_SAFE;
  return (unsigned int)v;
}

/** A closed presence interval.  Stored compactly in the record. */
struct presence_interval {
  int64_t start;   /**< epoch seconds, inclusive */
  int64_t end;     /**< epoch seconds, inclusive (always >= start) */
};

/** Per-(anchor, channel) presence record.  Same layout for in-memory
 * session entries and the on-disk account record (memcpy'd to/from
 * the value buffer).  Endian-neutral within a single server (we never
 * migrate this data between hosts of differing endianness). */
struct presence_record {
  uint8_t  count;                                              /**< closed-interval count */
  int64_t  open_since;                                         /**< 0 if not currently open */
  struct presence_interval intervals[PRESENCE_MAX_INTERVALS];
};

/* ---------------------------------------------------------------- */
/* In-memory session-anchored store                                  */
/* ---------------------------------------------------------------- */

#define PRESENCE_HASH_BITS 10
#define PRESENCE_HASH_SIZE (1u << PRESENCE_HASH_BITS)
#define PRESENCE_HASH_MASK (PRESENCE_HASH_SIZE - 1u)

/** Hash chain entry for session-anchored records.  Allocated on the
 * heap and chained through @c hnext per bucket. */
struct presence_session_entry {
  struct presence_session_entry *hnext;
  char  session_id[S2S_SESSID_BUFSIZE];
  char  channel[CHANNELLEN + 1];
  struct presence_record record;
};

static struct presence_session_entry *session_buckets[PRESENCE_HASH_SIZE];

/* ---------------------------------------------------------------- */
/* Persistent account-anchored store                                 */
/* ---------------------------------------------------------------- */

static struct db_cf *presence_cf = NULL;
static int           presence_persistence_ready = 0;

/* ---------------------------------------------------------------- */
/* Helpers                                                            */
/* ---------------------------------------------------------------- */

/** Case-fold one byte using the ircd's casemapping (rfc1459: {|}~ fold
 * to [\\]^, plus the Latin-1 ranges) -- the ASCII-only fold this used
 * to be disagreed with ircd_strcmp/FindChannel, so equivalently-named
 * channels could hash to different buckets and key different rows,
 * silently hiding history (fail-safe direction, but a real hole).
 * Old rows keyed under the ASCII fold become stale and age out via the
 * retention sweep. */
static inline unsigned char to_lower_ascii(unsigned char c)
{
  /* ToLower indexes its table from CHAR_MIN, i.e. by a plain char; an
   * unsigned byte above 127 would index past it. */
  return (unsigned char)ToLower((char)c);
}

/** FNV-1a over a session_id + channel pair, case-folding the channel. */
static unsigned int hash_session_key(const char *session_id, const char *channel)
{
  unsigned int h = 2166136261u;
  const char *p;
  for (p = session_id; *p; p++) {
    h ^= (unsigned char)*p;
    h *= 16777619u;
  }
  /* Separator byte so "abc"+"def" and "abcd"+"ef" don't collide. */
  h ^= 0;
  h *= 16777619u;
  for (p = channel; *p; p++) {
    h ^= to_lower_ascii((unsigned char)*p);
    h *= 16777619u;
  }
  return h & PRESENCE_HASH_MASK;
}

/** Find an existing in-memory record.  Returns NULL if absent. */
static struct presence_session_entry *session_find(const char *session_id,
                                                    const char *channel)
{
  unsigned int b = hash_session_key(session_id, channel);
  struct presence_session_entry *e;
  for (e = session_buckets[b]; e; e = e->hnext) {
    if (0 == strcmp(e->session_id, session_id)
        && 0 == ircd_strcmp(e->channel, channel))
      return e;
  }
  return NULL;
}

/** Find or create an in-memory record.  Newly-created entries have a
 * zero presence_record (no intervals, not open). */
static struct presence_session_entry *session_get_or_create(
    const char *session_id, const char *channel)
{
  struct presence_session_entry *e = session_find(session_id, channel);
  unsigned int b;
  if (e)
    return e;
  e = (struct presence_session_entry *)MyCalloc(1, sizeof(*e));
  ircd_strncpy(e->session_id, session_id, sizeof(e->session_id));
  ircd_strncpy(e->channel, channel, sizeof(e->channel));
  b = hash_session_key(session_id, channel);
  e->hnext = session_buckets[b];
  session_buckets[b] = e;
  return e;
}

/** Unlink and free a session entry from its bucket chain. */
static void session_unlink_and_free(struct presence_session_entry *target)
{
  unsigned int b = hash_session_key(target->session_id, target->channel);
  struct presence_session_entry **pp;
  for (pp = &session_buckets[b]; *pp; pp = &(*pp)->hnext) {
    if (*pp == target) {
      *pp = target->hnext;
      MyFree(target);
      return;
    }
  }
}

/** Build the account-anchored CF key: "account\0<lowercased channel>".
 * Returns the key length in bytes (including the embedded NUL but
 * excluding any trailing NUL on the channel side — keys are binary).
 * Returns 0 if the inputs don't fit @a bufsz. */
static size_t build_acct_key(char *buf, size_t bufsz,
                              const char *account, const char *channel)
{
  size_t alen = strlen(account);
  size_t clen = strlen(channel);
  size_t i;
  if (alen + 1u + clen > bufsz)
    return 0;
  memcpy(buf, account, alen);
  buf[alen] = '\0';
  for (i = 0; i < clen; i++)
    buf[alen + 1u + i] = (char)to_lower_ascii((unsigned char)channel[i]);
  return alen + 1u + clen;
}

/** Load the account-anchored record from storage into @a out.  Returns
 * 0 on success, -1 if missing or unavailable.  Zero-fills @a out if
 * the stored record has an unexpected size (treats as missing). */
static int record_norm_ms(struct presence_record *r);  /* defined with the time helpers */

static int acct_load(const char *account, const char *channel,
                     struct presence_record *out)
{
  struct db_env *env;
  char keybuf[ACCOUNTLEN + 1 + CHANNELLEN + 1];
  size_t klen;
  struct db_val v;
  int rc;

  memset(out, 0, sizeof(*out));
  if (!presence_persistence_ready || !presence_cf)
    return -1;
  env = metadata_get_env();
  if (!env)
    return -1;
  klen = build_acct_key(keybuf, sizeof(keybuf), account, channel);
  if (klen == 0)
    return -1;

  memset(&v, 0, sizeof(v));
  rc = db_get(env, presence_cf, keybuf, klen, NULL, &v);
  if (rc != DB_OK)
    return -1;
  if (v.len == sizeof(*out)) {
    memcpy(out, v.base, sizeof(*out));
    record_norm_ms(out);   /* seconds-era record: read as milliseconds */
  }
  /* Else: leave @a out zeroed.  Caller will write a fresh record next
   * time anything mutates state, which is the right behavior. */
  db_val_free(&v);
  return 0;
}

/** Store an account-anchored record.  Returns 0 on success.  If the
 * record has no closed intervals and no open marker, the row is
 * deleted instead of written — keeps the CF tidy. */
static int acct_store(const char *account, const char *channel,
                      const struct presence_record *r)
{
  struct db_env *env;
  struct db_writebatch *wb;
  char keybuf[ACCOUNTLEN + 1 + CHANNELLEN + 1];
  size_t klen;
  int rc;

  if (!presence_persistence_ready || !presence_cf)
    return -1;
  env = metadata_get_env();
  if (!env)
    return -1;
  klen = build_acct_key(keybuf, sizeof(keybuf), account, channel);
  if (klen == 0)
    return -1;

  wb = db_writebatch_new(env);
  if (!wb)
    return -1;

  if (r->count == 0 && r->open_since == 0)
    db_writebatch_del(wb, presence_cf, keybuf, klen);
  else
    db_writebatch_put(wb, presence_cf, keybuf, klen, r, sizeof(*r));

  rc = db_writebatch_commit(wb, /*sync_durably=*/0);
  db_writebatch_destroy(wb);
  return (rc == DB_OK) ? 0 : -1;
}

/* ---------------------------------------------------------------- */
/* Core interval algorithms (shared between in-memory and persistent) */
/* ---------------------------------------------------------------- */

/* ---------------------------------------------------------------- */
/* Presence time: packed HLC (ms << 16 | logical), since 2026-09-02   */
/* ---------------------------------------------------------------- */

int64_t presence_norm_time(int64_t v)
{
  /* Three eras by magnitude: seconds (~1.7e9, below 1e11), milliseconds
   * (~1.7e12, below 1e15 -- only ever on the bed), packed HLC (~1.1e17).
   * 1e11 is the year 5138 in seconds and March 1973 in milliseconds;
   * 1e15 is the year 33658 in milliseconds and 1970-01-01 plus 19
   * minutes packed. */
  if (v <= 0)
    return v;
  if (v < 100000000000LL)
    return PRESENCE_TIME_FROM_MS(v * 1000);
  if (v < 1000000000000000LL)
    return PRESENCE_TIME_FROM_MS(v);
  return v;
}

int64_t presence_event_time(const char *msgid, uint64_t event_ms)
{
  uint64_t ms = 0;
  uint16_t logical = 0;

  if (msgid && msgid[0] && msgid_decode_hlc(msgid, &ms, &logical)
      && (!event_ms || ms == event_ms))
    return PRESENCE_TIME_PACK(ms, logical);
  return PRESENCE_TIME_FROM_MS(event_ms);
}

/** Normalize a record read from disk (or replicated) in place.  Returns
 * nonzero when anything changed, so a sweep can rewrite it. */
static int record_norm_ms(struct presence_record *r)
{
  int changed = 0;
  uint8_t i;
  int64_t v;

  v = presence_norm_time(r->open_since);
  if (v != r->open_since) { r->open_since = v; changed = 1; }
  for (i = 0; i < r->count; i++) {
    v = presence_norm_time(r->intervals[i].start);
    if (v != r->intervals[i].start) { r->intervals[i].start = v; changed = 1; }
    v = presence_norm_time(r->intervals[i].end);
    if (v != r->intervals[i].end) { r->intervals[i].end = v; changed = 1; }
  }
  return changed;
}

/** The event time the membership hooks stamp with (see
 * presence_set_event_time); 0 = none armed. */
static int64_t presence_event_ctx = 0;

void presence_set_event_time(int64_t t)
{
  presence_event_ctx = t;
}

/** The HLC's current stamp as presence time (no event armed). */
static int64_t presence_clock_time(void)
{
  const struct HLC *h = hlc_global();
  return PRESENCE_TIME_PACK(h->physical_ms, h->logical);
}

/** Time for a hook: the armed event time, else the clock. */
static int64_t presence_now_time(void)
{
  if (presence_event_ctx > 0)
    return presence_event_ctx;
  return presence_clock_time();
}

/** Open a new interval if none is open.  Idempotent. */
static void record_apply_join(struct presence_record *r, int64_t when)
{
  if (r->open_since == 0)
    r->open_since = (int64_t)when;
}

/** Close the open interval, appending it to the closed list.  Drops
 * the oldest closed interval if the cap would be exceeded (hard FIFO
 * — fail-safe).  No-op if no interval is open. */
static void record_apply_part(struct presence_record *r, int64_t when)
{
  int64_t end = when;
  if (r->open_since == 0)
    return;
  if (end < r->open_since) {
    /* Clock skew or out-of-order event: clamp to a zero-length visit
     * instead of discarding -- a discarded open erased the member's
     * entire real window under a backward clock step. */
    end = r->open_since;
  }
  /* Coalesce with the previous closed interval when the gap is tiny
   * (reconnect churn): a flaky mobile client otherwise burns one
   * FIFO slot per reconnect and silently ages out its oldest real
   * windows.  30s covers reconnect blips without granting any
   * meaningful absence. */
  if (r->count > 0
      && r->intervals[r->count - 1].end + PRESENCE_COALESCE_TIME >= r->open_since) {
    if (end > r->intervals[r->count - 1].end)
      r->intervals[r->count - 1].end = end;
    r->open_since = 0;
    return;
  }
  {
    unsigned int cap = effective_max_intervals();
    /* Trim down if the runtime cap was lowered below the current
     * count — drop oldest intervals first, then make room for the
     * new one if we're still at the cap. */
    while (r->count > cap) {
      memmove(&r->intervals[0], &r->intervals[1],
              sizeof(r->intervals[0]) * (r->count - 1u));
      r->count--;
    }
    if (r->count >= cap) {
      memmove(&r->intervals[0], &r->intervals[1],
              sizeof(r->intervals[0]) * (cap - 1u));
      r->count = (uint8_t)(cap - 1u);
    }
  }
  r->intervals[r->count].start = r->open_since;
  r->intervals[r->count].end = end;
  r->count++;
  r->open_since = 0;
}

/** Test whether @a msg_time falls inside any closed interval or the
 * currently-open one.  Closed intervals are checked inclusively on
 * both ends; the open interval is inclusive on its start. */
static int record_was_present(const struct presence_record *r, int64_t msg_ms)
{
  int64_t t = msg_ms;
  uint8_t i;
  if (r->open_since != 0 && t >= r->open_since)
    return 1;
  for (i = 0; i < r->count; i++) {
    if (t >= r->intervals[i].start && t <= r->intervals[i].end)
      return 1;
  }
  return 0;
}

/* ---------------------------------------------------------------- */
/* Public API                                                         */
/* ---------------------------------------------------------------- */

/** Meta row key for the last-alive stamp.  Account keys are
 * "<account>\\0<channel>" and accounts are never empty, so a leading
 * NUL can never collide with a real record. */
#define PRESENCE_META_LAST_ALIVE "\0\0last_alive"

/** Persist the current time as the last-alive stamp (see boot-close
 * in presence_init).  Called from init and each maintenance sweep. */
void presence_touch_last_alive(void)
{
  struct db_env *env;
  struct db_writebatch *wb;
  int64_t now = presence_clock_time();

  if (!presence_persistence_ready || !presence_cf)
    return;
  env = metadata_get_env();
  if (!env)
    return;
  wb = db_writebatch_new(env);
  if (!wb)
    return;
  db_writebatch_put(wb, presence_cf, PRESENCE_META_LAST_ALIVE,
                    sizeof(PRESENCE_META_LAST_ALIVE) - 1,
                    &now, sizeof(now));
  (void)db_writebatch_commit(wb, /*sync_durably=*/0);
  db_writebatch_destroy(wb);
}

int presence_init(void)
{
  struct db_env *env;
  struct db_cf_opts cf_opts;
  int rc;

  /* In-memory tables are already zero-initialized at static scope;
   * nothing to do for the session-anchored side. */

  env = metadata_get_env();
  if (!env) {
    /* History storage isn't up yet (or is disabled).  Session-anchored
     * presence still works; account-anchored is silently unavailable. */
    presence_cf = NULL;
    presence_persistence_ready = 0;
    return -1;
  }

  memset(&cf_opts, 0, sizeof(cf_opts));
  rc = db_cf_open(env, "presence", &cf_opts, &presence_cf);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "presence: db_cf_open(presence) failed: %s — "
              "account-anchored presence disabled",
              db_strerror(rc));
    presence_cf = NULL;
    presence_persistence_ready = 0;
    return -1;
  }

  presence_persistence_ready = 1;

  /* Boot-close stale open intervals.  Nothing exits clients at
   * shutdown (server_die only flushes sockets), so every account-
   * anchored member of every channel is left with open_since set on
   * disk -- and an open interval is unbounded FORWARD: a member
   * removed from the channel during downtime could read everything
   * since their last join, forever.  Close every open interval at the
   * last-alive stamp (updated each maintenance sweep; granularity
   * costs at most one sweep interval of real presence, fail-safe),
   * clamped no earlier than the interval's own start.  Members still
   * welcome re-open naturally when they rejoin after reconnect. */
  {
    struct db_iter *it = db_iter_open(env, presence_cf, NULL);
    struct db_writebatch *wb = it ? db_writebatch_new(env) : NULL;
    int64_t last_alive = 0;
    unsigned int closed = 0;
    struct db_val v;

    memset(&v, 0, sizeof(v));
    if (db_get(env, presence_cf, PRESENCE_META_LAST_ALIVE,
               sizeof(PRESENCE_META_LAST_ALIVE) - 1, NULL, &v) == DB_OK) {
      if (v.len == sizeof(last_alive))
        memcpy(&last_alive, v.base, sizeof(last_alive));
      last_alive = presence_norm_time(last_alive);
      db_val_free(&v);
    }

    if (it && wb && db_iter_seek_first(it) == DB_OK) {
      while (db_iter_valid(it)) {
        size_t klen, vlen;
        const void *kptr = db_iter_key(it, &klen);
        const void *vptr = db_iter_value(it, &vlen);
        struct presence_record r;

        if (vptr && vlen == sizeof(r) && kptr && klen > 0) {
          memcpy(&r, vptr, sizeof(r));
          record_norm_ms(&r);
          if (r.open_since != 0) {
            int64_t end = last_alive;
            if (end < r.open_since)
              end = r.open_since;   /* zero-length: keep the join instant */
            record_apply_part(&r, end);
            db_writebatch_put(wb, presence_cf, kptr, klen, &r, sizeof(r));
            closed++;
          }
        }
        if (db_iter_next(it) != DB_OK)
          break;
      }
    }
    if (it)
      db_iter_close(it);
    if (wb) {
      if (db_writebatch_count(wb) > 0)
        (void)db_writebatch_commit(wb, /*sync_durably=*/0);
      db_writebatch_destroy(wb);
    }
    if (closed)
      log_write(LS_SYSTEM, L_INFO, 0,
                "presence: boot-closed %u stale open interval(s) at "
                "last-alive %ld", closed, (long)last_alive);
    presence_touch_last_alive();
  }
  return 0;
}

void presence_shutdown(void)
{
  unsigned int i;
  /* Free in-memory session entries. */
  for (i = 0; i < PRESENCE_HASH_SIZE; i++) {
    struct presence_session_entry *e = session_buckets[i];
    while (e) {
      struct presence_session_entry *next = e->hnext;
      MyFree(e);
      e = next;
    }
    session_buckets[i] = NULL;
  }
  /* CF handle is closed implicitly by db_env_close in history_shutdown;
   * just drop our reference. */
  presence_cf = NULL;
  presence_persistence_ready = 0;
}

/** Union-merge one closed interval [start,end] into @a r, preserving
 * sort order, coalescing overlaps (and near-adjacency, same 30s policy
 * as record_apply_part), leaving any open interval untouched, and
 * FIFO-dropping the oldest closed interval at the cap.  The merge is
 * idempotent and order-independent -- the properties the PN
 * replication flood needs. */
static void record_union_close(struct presence_record *r,
                               int64_t start, int64_t end)
{
  unsigned int cap = effective_max_intervals();
  uint8_t i, pos;

  if (end < start)
    end = start;   /* degenerate input: clamp to zero-length */

  /* Find insertion position (intervals are sorted by start). */
  for (pos = 0; pos < r->count && r->intervals[pos].start <= start; pos++)
    ;

  /* Merge with predecessor when overlapping/adjacent. */
  if (pos > 0 && r->intervals[pos - 1].end + PRESENCE_COALESCE_TIME >= start) {
    if (end > r->intervals[pos - 1].end)
      r->intervals[pos - 1].end = end;
    pos--;
  } else {
    /* Insert at pos. */
    while (r->count > cap) {   /* runtime cap lowered under us */
      memmove(&r->intervals[0], &r->intervals[1],
              sizeof(r->intervals[0]) * (r->count - 1u));
      r->count--;
      if (pos > 0) pos--;
    }
    if (r->count >= cap) {
      if (pos == 0)
        return;   /* older than everything retained -- drop it */
      memmove(&r->intervals[0], &r->intervals[1],
              sizeof(r->intervals[0]) * (pos - 1u));
      pos--;
      r->count--;
    }
    memmove(&r->intervals[pos + 1], &r->intervals[pos],
            sizeof(r->intervals[0]) * (r->count - pos));
    r->intervals[pos].start = start;
    r->intervals[pos].end = end;
    r->count++;
  }

  /* Swallow successors the (possibly grown) interval now covers. */
  i = pos;
  while (i + 1 < r->count
         && r->intervals[i].end + PRESENCE_COALESCE_TIME >= r->intervals[i + 1].start) {
    if (r->intervals[i + 1].end > r->intervals[i].end)
      r->intervals[i].end = r->intervals[i + 1].end;
    memmove(&r->intervals[i + 1], &r->intervals[i + 2],
            sizeof(r->intervals[0]) * (r->count - i - 2u));
    r->count--;
  }
}

void presence_apply_close(const char *anchor, int anchor_is_session,
                          const char *channel, int64_t start, int64_t end)
{
  if (!anchor || !*anchor || !channel || !*channel)
    return;

  if (anchor_is_session) {
    struct presence_session_entry *e =
        session_get_or_create(anchor, channel);
    record_union_close(&e->record, (int64_t)start, (int64_t)end);
    return;
  }

  {
    struct presence_record r;
    if (acct_load(anchor, channel, &r) != 0)
      memset(&r, 0, sizeof(r));
    record_union_close(&r, (int64_t)start, (int64_t)end);
    (void)acct_store(anchor, channel, &r);
  }
}

/** Broadcast a closed account interval to all servers (PN token).
 * Readmarker-style flood; receivers apply via presence_apply_close and
 * relay butone.  Gated on the feature (no traffic while strict
 * presence is dark) and on server init (conf-parse safety). */
static void presence_broadcast_close(const char *account,
                                     const char *channel,
                                     int64_t start, int64_t end)
{
  char sb[24], eb[24];

  if (!feature_bool(FEAT_CHATHISTORY_STRICT_PRESENCE))
    return;
  if (!cli_serv(&me))
    return;
  /* Epoch milliseconds on the wire (2026-09-02); receivers normalize
   * seconds-era values from older peers by magnitude. */
  snprintf(sb, sizeof(sb), "%lld", (long long)start);
  snprintf(eb, sizeof(eb), "%lld", (long long)end);
  sendcmdto_serv_butone_v3(&me, CMD_PRESENCE, NULL, "%s %s %s %s",
                           account, channel, sb, eb);
}

void presence_record_join(const char *anchor, int anchor_is_session,
                           const char *channel, time_t when)
{
  if (!anchor || !*anchor || !channel || !*channel)
    return;

  if (anchor_is_session) {
    struct presence_session_entry *e =
        session_get_or_create(anchor, channel);
    record_apply_join(&e->record, when);
    return;
  }

  /* Account-anchored: load, mutate, store. */
  {
    struct presence_record r;
    if (acct_load(anchor, channel, &r) != 0)
      memset(&r, 0, sizeof(r));   /* fresh record — load returns -1 on miss */
    record_apply_join(&r, when);
    (void)acct_store(anchor, channel, &r);
  }
}

void presence_record_part(const char *anchor, int anchor_is_session,
                           const char *channel, time_t when)
{
  if (!anchor || !*anchor || !channel || !*channel)
    return;

  if (anchor_is_session) {
    struct presence_session_entry *e = session_find(anchor, channel);
    if (!e)
      return;  /* no open interval — no-op */
    record_apply_part(&e->record, when);
    /* If the record is now empty (no intervals, no open marker), drop
     * the entry to keep the table tidy. */
    if (e->record.count == 0 && e->record.open_since == 0)
      session_unlink_and_free(e);
    return;
  }

  {
    struct presence_record r;
    int64_t was_open;
    if (acct_load(anchor, channel, &r) != 0)
      return;  /* nothing to close */
    was_open = r.open_since;
    record_apply_part(&r, when);
    (void)acct_store(anchor, channel, &r);
    /* Replicate the just-closed window (#6, metadata-layer
     * replication): peers union it into their own view, healing
     * netsplit windows and roaming.  Only account anchors replicate;
     * session anchors are connection-local by nature. */
    if (was_open != 0) {
      int64_t bstart = was_open;
      int64_t bend = (int64_t)when;
      if (bend < bstart)
        bend = bstart;
      presence_broadcast_close(anchor, channel,
                               (time_t)bstart, (time_t)bend);
    }
  }
}

int presence_was_present(const char *anchor, int anchor_is_session,
                          const char *channel, int64_t t)
{
  if (!anchor || !*anchor || !channel || !*channel)
    return 0;

  if (anchor_is_session) {
    struct presence_session_entry *e = session_find(anchor, channel);
    if (!e)
      return 0;
    return record_was_present(&e->record, t);
  }

  {
    struct presence_record r;
    if (acct_load(anchor, channel, &r) != 0)
      return 0;
    return record_was_present(&r, t);
  }
}

/** Nearest presence boundary in the walk direction (see the header).
 * Pure interval logic over one record: forward = smallest closed start
 * (or open_since) strictly after @a t; backward = largest closed end
 * strictly before @a t.  Inside a window the answer is @a t. */
static int64_t record_next_visible(const struct presence_record *r,
                                   int64_t t, int reverse)
{
  int64_t best = -1;
  uint8_t i;

  if (record_was_present(r, t))
    return t;

  if (!reverse) {
    if (r->open_since != 0 && r->open_since > t)
      best = r->open_since;
    for (i = 0; i < r->count; i++) {
      if (r->intervals[i].start > t
          && (best < 0 || r->intervals[i].start < best))
        best = r->intervals[i].start;
    }
  } else {
    /* An open interval starts after every closed one and (t not being
     * inside it) lies entirely after t, so only closed ends qualify. */
    for (i = 0; i < r->count; i++) {
      if (r->intervals[i].end < t && r->intervals[i].end > best)
        best = r->intervals[i].end;
    }
  }
  return best;
}

int64_t presence_next_visible(const char *anchor, int anchor_is_session,
                              const char *channel, int64_t t, int reverse)
{
  if (!anchor || !*anchor || !channel || !*channel)
    return -1;

  if (anchor_is_session) {
    struct presence_session_entry *e = session_find(anchor, channel);
    if (!e)
      return -1;
    return record_next_visible(&e->record, t, reverse);
  }

  {
    struct presence_record r;
    if (acct_load(anchor, channel, &r) != 0)
      return -1;
    return record_next_visible(&r, t, reverse);
  }
}

const char *presence_anchor_for(const struct Client *cli,
                                 int *is_session_out)
{
  const char *acct;
  if (!cli)
    return NULL;
  if (IsAccount((struct Client *)cli)) {
    acct = cli_user((struct Client *)cli) ? cli_user((struct Client *)cli)->account : NULL;
    if (acct && *acct) {
      if (is_session_out) *is_session_out = 0;
      return acct;
    }
  }
  if (cli_session_id((struct Client *)cli)[0]) {
    if (is_session_out) *is_session_out = 1;
    return cli_session_id((struct Client *)cli);
  }
  return NULL;
}

/** Walk a channel's members, returning nonzero iff some Client other
 * than @a exclude resolves to the same (anchor, anchor_is_session) as
 * the caller wants to check.  Used to gate presence record_join /
 * record_part on the bouncer-aliases case: presence is per-anchor
 * (account or session_id), so the first sibling drives the interval
 * and subsequent siblings are no-ops.  O(channel members) in the
 * worst case, but presence hooks fire only on JOIN/PART/KICK/QUIT —
 * not on every message — and the loop exits early on first match. */
static int anchor_sibling_in_channel(const struct Client *exclude,
                                      struct Channel *chptr,
                                      const char *anchor,
                                      int anchor_is_session)
{
  struct Membership *m;
  for (m = chptr->members; m; m = m->next_member) {
    struct Client *c = m->user;
    int other_is_session = 0;
    const char *other_anchor;
    if (c == exclude || !c)
      continue;
    /* Alias memberships never open/close intervals themselves and must
     * not suppress the primary's interval either.  Without this skip,
     * add_user_to_channel's bounce_sync_alias_join adds the alias
     * BEFORE the primary's presence hook runs -- primary and alias
     * then each saw the other as an existing sibling and NO interval
     * ever opened for bouncer accounts (the feature's main audience). */
    if (IsMemberAlias(m))
      continue;
    other_anchor = presence_anchor_for(c, &other_is_session);
    if (!other_anchor)
      continue;
    if (other_is_session != anchor_is_session)
      continue;
    if (anchor_is_session
        ? (0 == strcmp(other_anchor, anchor))
        : (0 == ircd_strcmp(other_anchor, anchor)))
      return 1;
  }
  return 0;
}

void presence_on_channel_add(struct Client *who, struct Channel *chptr)
{
  const char *anchor;
  int is_session = 0;

  if (!feature_bool(FEAT_CHATHISTORY_STRICT_PRESENCE))
    return;
  if (!who || !chptr || !chptr->chname[0])
    return;

  anchor = presence_anchor_for(who, &is_session);
  if (!anchor)
    return;

  /* @a who has already been added to chptr->members by the caller, so
   * the walk excludes @a who to find pre-existing siblings.  If any
   * sibling is in the channel, this isn't the first connection of the
   * anchor — leave the existing open interval alone. */
  if (anchor_sibling_in_channel(who, chptr, anchor, is_session))
    return;

  presence_record_join(anchor, is_session, chptr->chname, presence_now_time());
}

void presence_on_channel_remove(struct Client *who, struct Channel *chptr)
{
  const char *anchor;
  int is_session = 0;

  if (!feature_bool(FEAT_CHATHISTORY_STRICT_PRESENCE))
    return;
  if (!who || !chptr || !chptr->chname[0])
    return;

  anchor = presence_anchor_for(who, &is_session);
  if (!anchor)
    return;

  /* Called BEFORE remove_member_from_channel, so @a who is still in
   * chptr->members; the walk excludes @a who to find remaining
   * siblings.  Close the interval only when no sibling remains. */
  if (anchor_sibling_in_channel(who, chptr, anchor, is_session))
    return;

  presence_record_part(anchor, is_session, chptr->chname, presence_now_time());
}

/** Open an interval NOW for every current non-alias member of every
 * channel.  Called when FEAT_CHATHISTORY_STRICT_PRESENCE flips ON at
 * runtime: pre-existing memberships otherwise have no open interval
 * (the join hook early-returns while the feature is off) and their
 * holders see empty history until they part and rejoin. */
void presence_backfill_now(void)
{
  struct Channel *chptr;

  for (chptr = GlobalChannelList; chptr; chptr = chptr->next) {
    struct Membership *m;
    for (m = chptr->members; m; m = m->next_member) {
      const char *anchor;
      int is_session = 0;
      if (!m->user || IsMemberAlias(m) || IsZombie(m))
        continue;
      anchor = presence_anchor_for(m->user, &is_session);
      if (!anchor)
        continue;
      /* record_apply_join is idempotent, so same-anchor siblings are
       * naturally collapsed. */
      presence_record_join(anchor, is_session, chptr->chname, presence_now_time());
    }
  }
  log_write(LS_SYSTEM, L_INFO, 0,
            "presence: strict-presence enabled -- backfilled open "
            "intervals for current channel members");
}

/** Move a client's presence from one anchor to another across an
 * account-state transition (unauthed<->authed, or an account CHANGE).
 * The mirror of channel_account_adjust: the join/part hooks evaluate
 * the anchor at hook time, so a mid-membership FLAG_ACCOUNT flip
 * otherwise strands the open interval under the old anchor (the part
 * under the new anchor misses it -> never closes -> unbounded forward
 * visibility after deauth) and the new anchor shows no presence at
 * all for the current window.
 *
 * The open-interval START carries over on auth (session->account and
 * account rename) so the member's continuous physical presence stays
 * one window; the old anchor's interval is closed at now.  Closed
 * historical intervals are NOT migrated (documented residue: presence
 * recorded while unauthed stays queryable only... under the account
 * they later authed to?  No -- it ages out unqueried; acceptable).
 *
 * Skips CHFL_ALIAS memberships and respects same-anchor siblings on
 * the closing side. */
void presence_anchor_transfer(struct Client *cptr,
                              const char *old_anchor, int old_is_session,
                              const char *new_anchor, int new_is_session)
{
  struct Membership *m;

  if (!feature_bool(FEAT_CHATHISTORY_STRICT_PRESENCE))
    return;
  if (!cptr || !cli_user(cptr) || !new_anchor || !*new_anchor)
    return;

  for (m = cli_user(cptr)->channel; m; m = m->next_channel) {
    struct Channel *chptr = m->channel;
    int64_t now = presence_now_time();
    int64_t start = now;

    if (IsMemberAlias(m) || !chptr)
      continue;

    /* Carry the open-interval start across the transition when the
     * old anchor holds one. */
    if (old_anchor && *old_anchor) {
      if (old_is_session) {
        struct presence_session_entry *e =
            session_find(old_anchor, chptr->chname);
        if (e && e->record.open_since != 0
            && e->record.open_since < start)
          start = e->record.open_since;
      } else {
        struct presence_record r;
        if (acct_load(old_anchor, chptr->chname, &r) == 0
            && r.open_since != 0 && r.open_since < start)
          start = r.open_since;
      }
      /* Close the old anchor's interval unless a same-old-anchor
       * sibling remains (another connection of the same account). */
      if (!anchor_sibling_in_channel(cptr, chptr, old_anchor,
                                     old_is_session))
        presence_record_part(old_anchor, old_is_session, chptr->chname, now);
    }

    presence_record_join(new_anchor, new_is_session, chptr->chname, start);
  }
}

/** Link-time catch-up (#6 step 2): send this server's account-anchored
 * closed intervals to a newly-linked peer as PN lines.  Windows that
 * closed while the peer was unreachable (netsplit, downtime, a brand
 * new server) were never observed there and their PN broadcasts were
 * lost -- without this sync the steady-state flood only re-covers what
 * per-server observation already records.  Union application on the
 * receiver makes re-sends across repeated relinks harmless.
 * Bounded by the per-record FIFO cap and the retention sweep; a hard
 * line ceiling guards pathological stores. */
void presence_burst_sync(struct Client *cptr)
{
  struct db_env *env;
  struct db_iter *it;
  unsigned int sent = 0;
  const unsigned int line_ceiling = 20000;

  if (!feature_bool(FEAT_CHATHISTORY_STRICT_PRESENCE))
    return;
  if (!presence_persistence_ready || !presence_cf)
    return;
  env = metadata_get_env();
  if (!env)
    return;

  it = db_iter_open(env, presence_cf, NULL);
  if (!it)
    return;
  if (db_iter_seek_first(it) == DB_OK) {
    while (db_iter_valid(it) && sent < line_ceiling) {
      size_t klen, vlen;
      const void *kptr = db_iter_key(it, &klen);
      const void *vptr = db_iter_value(it, &vlen);
      struct presence_record r;

      /* Key: "<account>\0<channel>"; the meta row starts with NUL and
       * its value size differs from the record -- both checks skip it. */
      if (kptr && klen > 2 && ((const char *)kptr)[0] != '\0'
          && vptr && vlen == sizeof(r)) {
        const char *account = (const char *)kptr;
        size_t alen = strnlen(account, klen);
        if (alen < klen) {
          const char *channel = account + alen + 1;
          size_t clen = klen - alen - 1;
          char chanbuf[CHANNELLEN + 1];
          uint8_t k;
          if (clen > 0 && clen <= CHANNELLEN) {
            memcpy(chanbuf, channel, clen);
            chanbuf[clen] = '\0';
            memcpy(&r, vptr, sizeof(r));
            record_norm_ms(&r);
            for (k = 0; k < r.count && sent < line_ceiling; k++) {
              char sb[24], eb[24];
              snprintf(sb, sizeof(sb), "%lld", (long long)r.intervals[k].start);
              snprintf(eb, sizeof(eb), "%lld", (long long)r.intervals[k].end);
              sendcmdto_one(&me, CMD_PRESENCE, cptr, "%s %s %s %s",
                            account, chanbuf, sb, eb);
              sent++;
            }
          }
        }
      }
      if (db_iter_next(it) != DB_OK)
        break;
    }
  }
  db_iter_close(it);
  if (sent)
    log_write(LS_SYSTEM, L_INFO, 0,
              "presence: burst-synced %u interval(s) to %s",
              sent, cli_name(cptr));
}

void presence_purge_session(const char *session_id)
{
  unsigned int i;
  if (!session_id || !*session_id)
    return;
  /* Walk every bucket — session_id participates in the hash but @a
   * channel is what disambiguates entries for the same session; we
   * have to drop them all.  In practice each session has a small
   * number of channel records, but the table layout doesn't index
   * by session_id alone, so a full sweep is the simplest correct
   * answer.  Fine for connection-exit frequency. */
  for (i = 0; i < PRESENCE_HASH_SIZE; i++) {
    struct presence_session_entry **pp = &session_buckets[i];
    while (*pp) {
      if (0 == strcmp((*pp)->session_id, session_id)) {
        struct presence_session_entry *doomed = *pp;
        *pp = doomed->hnext;
        MyFree(doomed);
      } else {
        pp = &(*pp)->hnext;
      }
    }
  }
}

/** A history row's presence time: its msgid's HLC stamp (validated
 * against the row's millisecond stamp), else (row ms, 0).  0 when the
 * stamp is unparseable. */
static int64_t row_presence_time(const struct HistoryMessage *m)
{
  uint64_t ms = history_parse_ms(m->timestamp);
  if (!ms)
    return 0;
  return presence_event_time(m->msgid, ms);
}

int presence_filter_messages(struct Client *requestor,
                              const char *target,
                              struct HistoryMessage **head,
                              int count_in,
                              int ops_override)
{
  struct Channel *chptr;
  const char *anchor;
  int is_session = 0;
  struct HistoryMessage **pp;
  int kept = 0, dropped = 0;

  if (!head || !*head || count_in <= 0)
    return count_in;
  if (!feature_bool(FEAT_CHATHISTORY_STRICT_PRESENCE))
    return count_in;
  if (ops_override)
    return count_in;
  if (!target || !IsChannelName(target))
    return count_in;
  chptr = FindChannel(target);
  if (chptr && (chptr->mode.exmode & EXMODE_PUBLICHISTORY))
    return count_in;
  anchor = presence_anchor_for(requestor, &is_session);
  if (!anchor) {
    /* No resolvable anchor: fail CLOSED.  The old pass-through showed
     * the full result to a client whose identity state is broken
     * (e.g. FLAG_ACCOUNT set with an empty account string) -- the
     * comment claimed fail-safe while the code did the opposite. */
    history_free_messages(*head);
    *head = NULL;
    log_write(LS_SYSTEM, L_INFO, 0,
              "presence_filter_messages: target=%s requestor without anchor "
              "-- dropping %d message(s) (fail-closed)", target, count_in);
    return 0;
  }

  pp = head;
  while (*pp) {
    struct HistoryMessage *m = *pp;
    int64_t mtime = row_presence_time(m);
    /* Unparseable timestamp: fail CLOSED.  Locally-stored stamps are
     * server-generated, but federated rows arrive over the wire --
     * visible-if-unparseable was the wrong default for a security
     * gate. */
    int visible = (mtime != 0) &&
                  presence_was_present(anchor, is_session, target, mtime);

    /* Redaction inheritance: a HISTORY_REDACT entry's visibility is
     * the visibility of its target message, not its own timestamp.
     * Otherwise a user who saw the original but missed the redaction
     * would silently see un-redacted content — the redaction's purpose
     * is undermined.  Reactions / replies do NOT inherit (Phase B —
     * edits may join the inheritance set once their IRCv3 spec firms
     * up).  Orphan redact (parent already evicted) fails safe by
     * dropping the redact; the eviction cascade in a follow-up commit
     * eliminates this case at storage time. */
    if (!visible && m->type == HISTORY_REDACT
        && m->content[0]) {
      char target_msgid[64];
      char ts_buf[64];
      size_t i;
      /* m->content format: "target_msgid [:reason]".  First token. */
      for (i = 0; i < sizeof(target_msgid) - 1
                  && m->content[i]
                  && m->content[i] != ' '; i++)
        target_msgid[i] = m->content[i];
      target_msgid[i] = '\0';
      if (target_msgid[0]
          && history_msgid_to_timestamp(target_msgid, ts_buf) == 0) {
        int64_t parent_time = presence_event_time(target_msgid, history_parse_ms(ts_buf));
        if (parent_time != 0
            && presence_was_present(anchor, is_session, target, parent_time))
          visible = 1;
      }
    }

    if (visible) {
      pp = &m->next;
      kept++;
    } else {
      *pp = m->next;
      m->next = NULL;
      history_free_messages(m);
      dropped++;
    }
  }
  /* Diagnostic: when a full sweep drops everything, the user sees an
   * empty batch and has no way to tell strict-presence apart from
   * msgid-not-found.  Log the breakdown once per call so prod can
   * grep for it.  Silent on the common all-kept case. */
  if (dropped > 0)
    log_write(LS_SYSTEM, L_INFO, 0,
              "presence_filter_messages: target=%s anchor=%s%s kept=%d dropped=%d",
              target, anchor, is_session ? " (session)" : " (account)",
              kept, dropped);
  return kept;
}

/* ---------------------------------------------------------------- */
/* Query-time presence filter (presence-aware paging)                */
/* ---------------------------------------------------------------- */

struct PresenceQueryFilter {
  struct HistoryRowFilter hook;     /**< handed to history_query_*() */
  char channel[CHANNELLEN + 1];
  struct presence_record rec;       /**< ONE snapshot of the anchor's record
                                     *   (the post-filter re-loads per row) */
};

/** history.c row hook.  Presence is second-granular; a row exactly on a
 * boundary second is inside it (intervals are inclusive), which is what
 * lets the walk seek to a boundary and trust the landing row. */
static int presence_row_hook(const struct HistoryMessage *msg, int reverse,
                             void *ctx, int64_t *skip_to)
{
  struct PresenceQueryFilter *pf = (struct PresenceQueryFilter *)ctx;
  int64_t t = row_presence_time(msg);
  int64_t next;

  /* Unparseable stamp: fail closed, step on (same rule as the
   * post-filter). */
  if (t == 0)
    return 0;
  if (record_was_present(&pf->rec, t))
    return 1;
  next = record_next_visible(&pf->rec, t, reverse);
  if (next < 0)
    return -1;              /* nothing further visible this way: stop */
  *skip_to = PRESENCE_TIME_MS(next);   /* the walk seeks by millisecond */
  return 0;
}

struct PresenceQueryFilter *presence_query_filter_open(
    struct Client *requestor, const char *target, int effective_override,
    int *rc_out)
{
  struct Channel *chptr;
  const char *anchor;
  int is_session = 0;
  struct PresenceQueryFilter *pf;

  if (rc_out)
    *rc_out = 0;
  if (!feature_bool(FEAT_CHATHISTORY_STRICT_PRESENCE))
    return NULL;
  if (effective_override)
    return NULL;
  if (!target || !IsChannelName(target))
    return NULL;
  chptr = FindChannel(target);
  if (chptr && (chptr->mode.exmode & EXMODE_PUBLICHISTORY))
    return NULL;

  anchor = presence_anchor_for(requestor, &is_session);
  if (!anchor) {
    /* Mirrors presence_filter_messages: broken identity state fails
     * CLOSED.  The caller answers an empty, complete page. */
    log_write(LS_SYSTEM, L_INFO, 0,
              "presence_query_filter_open: target=%s requestor without "
              "anchor -- failing closed", target);
    if (rc_out)
      *rc_out = -1;
    return NULL;
  }

  pf = (struct PresenceQueryFilter *)MyCalloc(1, sizeof(*pf));
  ircd_strncpy(pf->channel, target, sizeof(pf->channel));
  if (is_session) {
    struct presence_session_entry *e = session_find(anchor, target);
    if (e)
      pf->rec = e->record;
    /* else: zero record -- no presence at all, nothing visible */
  } else if (acct_load(anchor, target, &pf->rec) != 0) {
    /* Store unavailable or no record: a zero record hides everything,
     * exactly as presence_was_present() answers 0 here. */
    memset(&pf->rec, 0, sizeof(pf->rec));
  }
  pf->hook.fn = presence_row_hook;
  pf->hook.ctx = pf;
  if (rc_out)
    *rc_out = 1;
  return pf;
}

struct HistoryRowFilter *presence_query_filter_hook(struct PresenceQueryFilter *pf)
{
  return pf ? &pf->hook : NULL;
}

void presence_query_filter_close(struct PresenceQueryFilter *pf)
{
  if (pf)
    MyFree(pf);
}

void presence_retention_sweep(void)
{
  int retention_days = feature_int(FEAT_CHATHISTORY_RETENTION);
  int64_t cutoff;
  unsigned int i;

  /* Keep the crash-recovery stamp fresh regardless of retention
   * config -- the boot-close pass in presence_init depends on it. */
  presence_touch_last_alive();

  if (retention_days <= 0)
    return;
  cutoff = PRESENCE_TIME_FROM_MS((int64_t)hlc_global()->physical_ms
                                 - (int64_t)retention_days * 86400000LL);

  /* In-memory side first: drop fully-old intervals; truncate straddlers;
   * delete empty records. */
  for (i = 0; i < PRESENCE_HASH_SIZE; i++) {
    struct presence_session_entry **pp = &session_buckets[i];
    while (*pp) {
      struct presence_session_entry *e = *pp;
      uint8_t out = 0, k;
      for (k = 0; k < e->record.count; k++) {
        if (e->record.intervals[k].end < cutoff)
          continue;   /* fully older than retention; drop */
        if (e->record.intervals[k].start < cutoff)
          e->record.intervals[k].start = cutoff;  /* truncate leading edge */
        if (out != k)
          e->record.intervals[out] = e->record.intervals[k];
        out++;
      }
      e->record.count = out;
      if (e->record.count == 0 && e->record.open_since == 0) {
        *pp = e->hnext;
        MyFree(e);
        continue;
      }
      pp = &e->hnext;
    }
  }

  /* Account-anchored side: iterate the CF, rewrite or delete each row.
   * Cheap if the CF is small; chathistory's retention sweep runs once
   * every FEAT_CHATHISTORY_MAINTENANCE_INTERVAL seconds (default 300),
   * not on the hot path. */
  if (presence_persistence_ready && presence_cf) {
    struct db_env *env = metadata_get_env();
    struct db_iter *it;
    struct db_writebatch *wb;
    unsigned int rewritten = 0, deleted = 0;

    if (!env)
      return;
    it = db_iter_open(env, presence_cf, NULL);
    if (!it)
      return;
    wb = db_writebatch_new(env);
    if (!wb) {
      db_iter_close(it);
      return;
    }

    if (db_iter_seek_first(it) == DB_OK) {
      while (db_iter_valid(it)) {
        size_t klen, vlen;
        const void *kptr = db_iter_key(it, &klen);
        const void *vptr = db_iter_value(it, &vlen);
        struct presence_record r;
        uint8_t out = 0, k;
        int changed = 0;

        if (vlen == sizeof(r) && kptr && klen > 0) {
          memcpy(&r, vptr, sizeof(r));
          if (record_norm_ms(&r))
            changed = 1;   /* seconds-era row: rewrite in milliseconds */
          for (k = 0; k < r.count; k++) {
            if (r.intervals[k].end < cutoff) {
              changed = 1;
              continue;
            }
            if (r.intervals[k].start < cutoff) {
              r.intervals[k].start = cutoff;
              changed = 1;
            }
            if (out != k)
              r.intervals[out] = r.intervals[k];
            out++;
          }
          if (changed)
            r.count = out;
          if (r.count == 0 && r.open_since == 0) {
            db_writebatch_del(wb, presence_cf, kptr, klen);
            deleted++;
          } else if (changed) {
            db_writebatch_put(wb, presence_cf, kptr, klen, &r, sizeof(r));
            rewritten++;
          }
        }
        if (db_iter_next(it) != DB_OK)
          break;
      }
    }
    db_iter_close(it);

    if (db_writebatch_count(wb) > 0)
      (void)db_writebatch_commit(wb, /*sync_durably=*/0);
    db_writebatch_destroy(wb);

    if (rewritten || deleted)
      Debug((DEBUG_INFO,
             "presence: retention sweep rewrote %u, deleted %u rows",
             rewritten, deleted));
  }
}
