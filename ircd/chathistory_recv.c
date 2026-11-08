/*
 * IRC - Internet Relay Chat, ircd/chathistory_recv.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * See include/chathistory_recv.h.  Pure: no ircd dependencies, nothing
 * called outside this file and <string.h>; compiled standalone for the
 * cmocka suite (W5 Task 8).
 */
#include "config.h"

#include "chathistory_recv.h"

#include <string.h>

/** Close whatever window is open, backing its end off @a end_now_ms by
 * the slack.  Shared by rcv_close ("now") and rcv_boot_close ("the last
 * known-alive time") -- the two differ only in what they call that
 * reference point, never in the arithmetic. */
static void rcv_close_at(struct rcv_record *r, int64_t end_now_ms)
{
  int64_t start, end;

  if (!r || r->open_since == 0)
    return;                     /* nothing open: no-op */

  start = r->open_since;
  end = end_now_ms - RCV_CLOSE_SLACK_MS;
  r->open_since = 0;            /* closed either way */

  if (end < start)
    return;                     /* never outlived the slack: discard it */

  if (r->count == RCV_MAX) {
    /* FIFO: drop the oldest to make room for the newest. */
    memmove(&r->iv[0], &r->iv[1], (size_t)(RCV_MAX - 1) * sizeof(r->iv[0]));
    r->count--;
  }
  r->iv[r->count].start = start;
  r->iv[r->count].end = end;
  r->count++;
}

void rcv_open(struct rcv_record *r, int64_t start_ms)
{
  if (!r || r->open_since != 0)
    return;                     /* already open: no-op */
  r->open_since = start_ms;
}

void rcv_close(struct rcv_record *r, int64_t now_ms)
{
  rcv_close_at(r, now_ms);
}

void rcv_boot_close(struct rcv_record *r, int64_t alive_ms)
{
  rcv_close_at(r, alive_ms);
}

int rcv_covers(const struct rcv_record *r, int64_t lo_ms, int64_t hi_ms,
               int64_t now_ms)
{
  uint8_t i;

  if (!r || lo_ms > hi_ms)
    return 0;                    /* an inverted range is never "received" */

  for (i = 0; i < r->count; i++) {
    if (lo_ms >= r->iv[i].start && hi_ms <= r->iv[i].end)
      return 1;
  }

  if (r->open_since != 0 && lo_ms >= r->open_since && hi_ms <= now_ms)
    return 1;

  return 0;
}

void rcv_clip(struct rcv_record *r, int64_t upto_ms)
{
  uint8_t i, w;

  if (!r)
    return;

  for (i = 0, w = 0; i < r->count; i++) {
    struct rcv_interval iv = r->iv[i];

    if (iv.end <= upto_ms)
      continue;                 /* entirely at/before the floor: drop */
    if (iv.start <= upto_ms)
      iv.start = upto_ms + 1;   /* straddling: clip its start */
    r->iv[w++] = iv;
  }
  r->count = w;

  if (r->open_since != 0 && r->open_since <= upto_ms)
    r->open_since = upto_ms + 1;
}

/** Write @a v into @a p as 8 little-endian bytes. */
static void rcv_le_put64(unsigned char *p, int64_t v)
{
  uint64_t u = (uint64_t)v;
  int i;

  for (i = 0; i < 8; i++) {
    p[i] = (unsigned char)(u & 0xffU);
    u >>= 8;
  }
}

/** Read 8 little-endian bytes at @a p back into an int64_t. */
static int64_t rcv_le_get64(const unsigned char *p)
{
  uint64_t u = 0;
  int i;

  for (i = 7; i >= 0; i--)
    u = (u << 8) | (uint64_t)p[i];
  return (int64_t)u;
}

int rcv_pack(const struct rcv_record *r, unsigned char *buf, size_t size)
{
  size_t need;
  uint8_t i;

  if (!r || !buf || r->count > RCV_MAX)
    return -1;

  need = 2 + 8 + (size_t)r->count * 16;
  if (size < need)
    return -1;

  buf[0] = RCV_PACK_VERSION;
  buf[1] = r->count;
  rcv_le_put64(buf + 2, r->open_since);

  for (i = 0; i < r->count; i++) {
    unsigned char *p = buf + 10 + (size_t)i * 16;
    rcv_le_put64(p, r->iv[i].start);
    rcv_le_put64(p + 8, r->iv[i].end);
  }

  return (int)need;
}

int rcv_unpack(const unsigned char *buf, size_t len, struct rcv_record *r)
{
  uint8_t count, i;
  size_t need;

  if (!buf || !r || len < 2)
    return -1;

  if (buf[0] != RCV_PACK_VERSION)
    return -1;

  count = buf[1];
  if (count > RCV_MAX)
    return -1;

  need = 2 + 8 + (size_t)count * 16;
  if (len < need)
    return -1;

  memset(r, 0, sizeof(*r));
  r->count = count;
  r->open_since = rcv_le_get64(buf + 2);

  for (i = 0; i < count; i++) {
    const unsigned char *p = buf + 10 + (size_t)i * 16;
    r->iv[i].start = rcv_le_get64(p);
    r->iv[i].end = rcv_le_get64(p + 8);
  }

  return 0;
}

int64_t rcv_floor_raise(int64_t *hw, int64_t floor_ms)
{
  if (!hw)
    return floor_ms;
  if (floor_ms > *hw)
    *hw = floor_ms;
  return *hw;
}

void rcv_ms_pack(int64_t ms, unsigned char out[8])
{
  rcv_le_put64(out, ms);
}

int rcv_ms_unpack(const unsigned char *buf, size_t len, int64_t *ms)
{
  if (!buf || len != 8 || !ms)
    return -1;
  *ms = rcv_le_get64(buf);
  return 0;
}
