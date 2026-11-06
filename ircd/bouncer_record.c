/*
 * IRC - Internet Relay Chat, ircd/bouncer_record.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * See include/bouncer_record.h.  Uses the ircd headers for the record
 * structs only and calls nothing in the ircd: it is compiled standalone
 * for the cmocka suite.
 */
#include "config.h"

#include "bouncer_record.h"

#include <string.h>

/* Compile-time checks at file scope (the pre-C11 negative-array form). */
#define BR_CHECK(name, cond) \
  typedef char bounce_record_check_##name[(cond) ? 1 : -1]
#define BR_COUNT(type, field) \
  (sizeof(((struct type *)0)->field) / sizeof(((struct type *)0)->field[0]))

/* Each frozen layout keeps the array sizes its version was written with,
 * whatever the live BOUNCER_MAX_* constants are now (see the struct
 * comments in bouncer_session.h for the derivations).  The v8 alias array
 * once followed BOUNCER_MAX_ALIASES from 4 to 16, and every real v8 record
 * then failed its size check and was dropped. */
BR_CHECK(v7_history,  BR_COUNT(BounceSessionRecord_v7,  bsr_history)  == 10);
BR_CHECK(v7_channels, BR_COUNT(BounceSessionRecord_v7,  bsr_channels) == 50);
BR_CHECK(v8_history,  BR_COUNT(BounceSessionRecord_v8,  bsr_history)  == 10);
BR_CHECK(v8_channels, BR_COUNT(BounceSessionRecord_v8,  bsr_channels) == 50);
BR_CHECK(v8_aliases,  BR_COUNT(BounceSessionRecord_v8,  bsr_aliases)  == 4);
BR_CHECK(v9_history,  BR_COUNT(BounceSessionRecord_v9,  bsr_history)  == 10);
BR_CHECK(v9_channels, BR_COUNT(BounceSessionRecord_v9,  bsr_channels) == 50);
BR_CHECK(v9_aliases,  BR_COUNT(BounceSessionRecord_v9,  bsr_aliases)  == 4);
BR_CHECK(v10_history, BR_COUNT(BounceSessionRecord_v10, bsr_history)  == 10);
BR_CHECK(v10_channels, BR_COUNT(BounceSessionRecord_v10, bsr_channels) == 50);
BR_CHECK(v10_aliases, BR_COUNT(BounceSessionRecord_v10, bsr_aliases)  == 16);
BR_CHECK(v11_history, BR_COUNT(BounceSessionRecord_v11, bsr_history)  == 10);
BR_CHECK(v11_channels, BR_COUNT(BounceSessionRecord_v11, bsr_channels) == 50);
BR_CHECK(v11_aliases, BR_COUNT(BounceSessionRecord_v11, bsr_aliases)  == 16);

/* v10 and v11 records are read as prefixes of the current layout. */
BR_CHECK(v10_prefix, sizeof(struct BounceSessionRecord_v10)
                     == offsetof(struct BounceSessionRecord, bsr_snomask));
BR_CHECK(v11_prefix, sizeof(struct BounceSessionRecord_v11)
                     == offsetof(struct BounceSessionRecord, bsr_kc_id));

#if defined(__LP64__) || defined(_LP64)
/* The sizes each version's own build wrote (LP64, measured against the
 * headers of the commit that introduced the version).  A failure here
 * means a frozen layout moved; for the current one, it means the on-disk
 * format changed: bump BOUNCER_DB_VERSION and freeze a copy of the old
 * struct rather than editing this number. */
BR_CHECK(v7_size,  sizeof(struct BounceSessionRecord_v7)  == 14192);
BR_CHECK(v8_size,  sizeof(struct BounceSessionRecord_v8)  == 14320);
BR_CHECK(v9_size,  sizeof(struct BounceSessionRecord_v9)  == 14360);
BR_CHECK(v10_size, sizeof(struct BounceSessionRecord_v10) == 14648);
BR_CHECK(v11_size, sizeof(struct BounceSessionRecord_v11) == 14656);
BR_CHECK(v12_size, sizeof(struct BounceSessionRecord)     == 14680);
#endif

size_t bounce_record_size(uint32_t version)
{
  switch (version) {
  case BOUNCER_DB_VERSION: return sizeof(struct BounceSessionRecord);
  case 11: return sizeof(struct BounceSessionRecord_v11);
  case 10: return sizeof(struct BounceSessionRecord_v10);
  case 9:  return sizeof(struct BounceSessionRecord_v9);
  case 8:  return sizeof(struct BounceSessionRecord_v8);
  case 7:  return sizeof(struct BounceSessionRecord_v7);
  default: return 0;
  }
}

/* Copy a fixed-width on-disk string, which may lack its terminator, into
 * a buffer of the current layout. */
static void copy_str(char *dst, size_t dsize, const char *src, size_t ssize)
{
  size_t n = ssize < dsize - 1 ? ssize : dsize - 1;
  const char *nul = memchr(src, '\0', n);

  if (nul)
    n = nul - src;
  memcpy(dst, src, n);
  dst[n] = '\0';
}

#define COPY_STR(d, s, f) \
  copy_str((d)->f, sizeof((d)->f), (s)->f, sizeof((s)->f))

/* Copy an array and its count across layouts whose element types match
 * but whose lengths may not: no more than either side holds. */
#define BR_MIN(a, b) ((a) < (b) ? (a) : (b))
#define COPY_ARRAY(d, s, f, countf) do { \
    size_t n_ = BR_MIN(sizeof((d)->f), sizeof((s)->f)) / sizeof((d)->f[0]); \
    (void)sizeof(char[(sizeof((d)->f[0]) == sizeof((s)->f[0])) ? 1 : -1]); \
    memcpy((d)->f, (s)->f, n_ * sizeof((d)->f[0])); \
    (d)->countf = (s)->countf < n_ ? (s)->countf : n_; \
  } while (0)

/* The fields v7, v8 and v9 share with the current layout, under the same
 * names: everything but bsr_sessid (v7's is short), the alias roster (v8+)
 * and the oper grant (v9+). */
#define COPY_COMMON(d, s) do { \
    COPY_STR(d, s, bsr_account); \
    COPY_STR(d, s, bsr_token); \
    COPY_STR(d, s, bsr_name); \
    COPY_STR(d, s, bsr_origin); \
    (d)->bsr_hold_override = (s)->bsr_hold_override; \
    (d)->bsr_created = (s)->bsr_created; \
    (d)->bsr_disconnect_time = (s)->bsr_disconnect_time; \
    (d)->bsr_last_active = (s)->bsr_last_active; \
    (d)->bsr_last_msg_time = (s)->bsr_last_msg_time; \
    (d)->bsr_total_active = (s)->bsr_total_active; \
    (d)->bsr_attach_count = (s)->bsr_attach_count; \
    (d)->bsr_connect_count = (s)->bsr_connect_count; \
    COPY_STR(d, s, bsr_nick); \
    COPY_STR(d, s, bsr_username); \
    COPY_STR(d, s, bsr_realhost); \
    COPY_STR(d, s, bsr_host); \
    COPY_STR(d, s, bsr_realname); \
    COPY_STR(d, s, bsr_account_name); \
    (d)->bsr_acc_create = (s)->bsr_acc_create; \
    memcpy(&(d)->bsr_ip, &(s)->bsr_ip, sizeof((d)->bsr_ip)); \
    COPY_STR(d, s, bsr_sock_ip); \
    COPY_STR(d, s, bsr_sockhost); \
    (d)->bsr_listener_port = (s)->bsr_listener_port; \
    (d)->bsr_agg_sendB = (s)->bsr_agg_sendB; \
    (d)->bsr_agg_receiveB = (s)->bsr_agg_receiveB; \
    (d)->bsr_agg_sendM = (s)->bsr_agg_sendM; \
    (d)->bsr_agg_receiveM = (s)->bsr_agg_receiveM; \
    COPY_ARRAY(d, s, bsr_history, bsr_histcount); \
    COPY_ARRAY(d, s, bsr_channels, bsr_chancount); \
  } while (0)

enum BounceRecordStatus bounce_record_decode(const void *buf, size_t len,
                                             struct BounceSessionRecord *out,
                                             uint32_t *version)
{
  /* The old layouts are read from an aligned copy: the store's value
   * buffers carry no alignment guarantee. */
  union {
    struct BounceSessionRecord_v9 v9;
    struct BounceSessionRecord_v8 v8;
    struct BounceSessionRecord_v7 v7;
  } old;
  size_t want;

  *version = 0;
  /* Every version starts with a uint32 version field at offset 0. */
  if (len < sizeof(uint32_t))
    return BOUNCE_REC_UNKNOWN;
  memcpy(version, buf, sizeof(*version));

  want = bounce_record_size(*version);
  if (!want)
    return BOUNCE_REC_UNKNOWN;
  if (len != want)
    return BOUNCE_REC_BAD_SIZE;

  memset(out, 0, sizeof(*out));
  switch (*version) {
  case BOUNCER_DB_VERSION:
    memcpy(out, buf, len);
    return BOUNCE_REC_CURRENT;

  case 11:
    /* v12 without the trailing bsr_kc_id, which stays empty (the revive
     * adopts the login's id). */
  case 10:
    /* v11 without the trailing snomask fields, which stay zero (no mask
     * recorded: the oper grant falls back to the O:line's). */
    memcpy(out, buf, len);
    break;

  case 9:
    /* v10 with a 4-entry alias roster; the rest of the larger array stays
     * zero. */
    memcpy(&old.v9, buf, len);
    COPY_COMMON(out, &old.v9);
    COPY_STR(out, &old.v9, bsr_sessid);
    COPY_ARRAY(out, &old.v9, bsr_aliases, bsr_aliascount);
    COPY_STR(out, &old.v9, bsr_oper_name);
    out->bsr_oper_granted_at = old.v9.bsr_oper_granted_at;
    break;

  case 8:
    /* v9 without the oper grant, which stays zero (pre-v9 sessions had no
     * session-level grant). */
    memcpy(&old.v8, buf, len);
    COPY_COMMON(out, &old.v8);
    COPY_STR(out, &old.v8, bsr_sessid);
    COPY_ARRAY(out, &old.v8, bsr_aliases, bsr_aliascount);
    break;

  case 7:
    /* v8 without the alias roster (left empty: peers' BS A bursts refill
     * it) and with a short sessid, which the caller replaces with a
     * minted UUID v7. */
    memcpy(&old.v7, buf, len);
    COPY_COMMON(out, &old.v7);
    out->bsr_version = BOUNCER_DB_VERSION;
    return BOUNCE_REC_MIGRATED_V7;
  }

  out->bsr_version = BOUNCER_DB_VERSION;
  return BOUNCE_REC_MIGRATED;
}

int64_t bounce_record_stamp(const struct bounce_stamp_facts *f,
                            int64_t disconnect_time)
{
  /* A real time: a hold's.  Ours to bring back only when the ghost is
   * ours and held for the session's full hold. */
  if (disconnect_time != 0)
    return (f && f->held_here && !f->brief_hold) ? disconnect_time : 0;
  /* An unclean exit drops every connection of ours at once.  The session
   * is held here then only if its disconnect would hold it -- an active
   * session, its primary ours and live, logged in, the bouncer on, hold
   * wanted -- and no device of it lives on: our local devices go with us,
   * one on another server is promoted there by its split. */
  if (f && f->active && f->primary_live && f->logged_in && f->bouncer_on
      && f->wants_hold && f->remote_devices == 0)
    return BOUNCE_REC_HELD_AT_RESTART;
  return 0;
}

int bounce_record_marked(const struct BounceSessionRecord *rec)
{
  return rec->bsr_disconnect_time == BOUNCE_REC_HELD_AT_RESTART;
}

int64_t bounce_record_shutdown_stamp(const struct bounce_stamp_facts *f,
                                     int64_t disconnect_time, int64_t now)
{
  int64_t stamp = bounce_record_stamp(f, disconnect_time);

  /* The crash rule; a clean shutdown knows its own time. */
  return stamp == BOUNCE_REC_HELD_AT_RESTART ? now : stamp;
}

int64_t bounce_hold_length(const struct bounce_hold_rule *r,
                           uint32_t connect_count, int64_t total_active,
                           int64_t idle)
{
  int64_t earned;

  /* Earned: base, a quarter of base per connection, an hour per full
   * 24 h attached, capped; base alone for a session that never
   * connected. */
  if (connect_count == 0)
    earned = r->base;
  else {
    earned = r->base + (r->base * (int64_t)connect_count / 4);
    if (total_active > 0)
      earned += (total_active / 86400) * 3600;
    if (earned > r->max)
      earned = r->max;
  }

  /* Idle decay: after decay_pct of the earned hold, the part left then
   * halves for every further quarter of it; never below base. */
  if (r->decay_pct > 0) {
    int64_t decay_start = earned * r->decay_pct / 100;
    int64_t decay_unit = earned / 4;

    if (idle > decay_start && decay_unit > 0) {
      int64_t remaining = earned - decay_start;
      int64_t halvings = (idle - decay_start) / decay_unit;
      int64_t computed;

      while (halvings-- > 0 && remaining > 0)
        remaining /= 2;
      computed = decay_start + remaining;
      return computed < r->base ? r->base : computed;
    }
  }
  return earned;
}

enum BounceRestoreVerdict
bounce_record_restore(const struct BounceSessionRecord *rec,
                      const struct bounce_restore_clock *c,
                      int64_t *held_since)
{
  int64_t d = rec->bsr_disconnect_time;
  int64_t since, outage;

  if (d == BOUNCE_REC_HELD_AT_RESTART) {
    /* Live when the server went: held from the crash, the latest time it
     * is known alive with the session live.  No heartbeat (a build that
     * kept none): from now. */
    since = c->now;
    if (c->last_alive > 0) {
      since = c->last_alive;
      if (rec->bsr_last_active > since)
        since = rec->bsr_last_active;
      if (since > c->now)
        since = c->now;
    }
    outage = c->now - since;
    if (outage > c->max_hold
        || outage > bounce_hold_length(&c->hold, rec->bsr_connect_count,
                                       rec->bsr_total_active, outage))
      return BOUNCE_RESTORE_EXPIRED;
    if (held_since)
      *held_since = since;
    return BOUNCE_RESTORE_HELD_AT_CRASH;
  }
  /* 0: a live session's record no unclean exit brings back.  Any other
   * time before the epoch is expired by the elapsed check as well, and is
   * not subtracted (now - INT64_MIN overflows). */
  if (d <= 0)
    return BOUNCE_RESTORE_EXPIRED;
  if (c->now - d > c->max_hold)
    return BOUNCE_RESTORE_EXPIRED;
  if (held_since)
    *held_since = d;
  return BOUNCE_RESTORE_HELD;
}

/* ---- The heartbeat and the boot record (metadata env, default CF) ---- */

#define BOUNCE_ALIVE_REC_VERSION 1
#define BOUNCE_BOOT_REC_VERSION  1
/* version u32, state u32, start i64, count u32, pad u32 */
#define BOUNCE_BOOT_REC_HEADER   24

void bounce_alive_rec_encode(void *buf, int64_t t)
{
  uint32_t v = BOUNCE_ALIVE_REC_VERSION, pad = 0;
  unsigned char *b = buf;

  memcpy(b, &v, 4);
  memcpy(b + 4, &pad, 4);
  memcpy(b + 8, &t, 8);
}

int bounce_alive_rec_decode(const void *buf, size_t len, int64_t *t)
{
  const unsigned char *b = buf;
  uint32_t v;

  if (len != BOUNCE_ALIVE_REC_SIZE)
    return -1;
  memcpy(&v, b, 4);
  if (v != BOUNCE_ALIVE_REC_VERSION)
    return -1;
  memcpy(t, b + 8, 8);
  return 0;
}

size_t bounce_boot_rec_size(uint32_t count)
{
  return BOUNCE_BOOT_REC_HEADER + (size_t)count * BOUNCER_SESSID_LEN;
}

void bounce_boot_rec_put_header(void *buf, enum bounce_boot_state state,
                                int64_t start, uint32_t count)
{
  uint32_t v = BOUNCE_BOOT_REC_VERSION, st = (uint32_t)state, pad = 0;
  unsigned char *b = buf;

  memcpy(b, &v, 4);
  memcpy(b + 4, &st, 4);
  memcpy(b + 8, &start, 8);
  memcpy(b + 16, &count, 4);
  memcpy(b + 20, &pad, 4);
}

void bounce_boot_rec_put_id(void *buf, uint32_t i, const char *id)
{
  char *slot = (char *)buf + bounce_boot_rec_size(i);
  size_t n = strlen(id);

  if (n > BOUNCER_SESSID_LEN - 1)
    n = BOUNCER_SESSID_LEN - 1;
  memset(slot, 0, BOUNCER_SESSID_LEN);
  memcpy(slot, id, n);
}

int bounce_boot_rec_decode(const void *buf, size_t len,
                           enum bounce_boot_state *state, int64_t *start,
                           uint32_t *count)
{
  const unsigned char *b = buf;
  uint32_t v, st, n, i;

  if (len < BOUNCE_BOOT_REC_HEADER)
    return -1;
  memcpy(&v, b, 4);
  memcpy(&st, b + 4, 4);
  memcpy(&n, b + 16, 4);
  if (v != BOUNCE_BOOT_REC_VERSION
      || (st != BOUNCE_BOOT_RUNNING && st != BOUNCE_BOOT_SETTLED)
      || n > (len - BOUNCE_BOOT_REC_HEADER) / BOUNCER_SESSID_LEN
      || len != bounce_boot_rec_size(n))
    return -1;
  for (i = 0; i < n; i++)
    if (!memchr(b + bounce_boot_rec_size(i), '\0', BOUNCER_SESSID_LEN))
      return -1;
  *state = (enum bounce_boot_state)st;
  memcpy(start, b + 8, 8);
  *count = n;
  return 0;
}

const char *bounce_boot_rec_id(const void *buf, uint32_t i)
{
  return (const char *)buf + bounce_boot_rec_size(i);
}

int bounce_boot_lists(enum BounceRestoreVerdict v)
{
  /* Only what the crash restore brought back; a session held before the
   * crash restores as it always did. */
  return v == BOUNCE_RESTORE_HELD_AT_CRASH;
}

int bounce_restore_breaker(enum bounce_boot_state prev, int64_t prev_start,
                           int64_t last_alive, int64_t window)
{
  if (prev != BOUNCE_BOOT_RUNNING || window <= 0)
    return 0;
  /* Known alive for its whole window: the settle mark was lost, not a
   * start that died early. */
  if (last_alive > 0 && last_alive - prev_start >= window)
    return 0;
  return 1;
}
