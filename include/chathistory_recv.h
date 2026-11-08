/*
 * IRC - Internet Relay Chat, include/chathistory_recv.h
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
 * @brief Receive windows for chathistory federation (W5 Task 8): what a
 *   peer relationship has already received of one channel's history, so
 *   a later request only pulls what is missing.
 *
 * "Coverage" is reserved for the trim's retention floor
 * (history_trim.c); this is a separate record and is never called that.
 *
 * A record is a small set of disjoint, closed [start, end] intervals
 * (epoch ms, inclusive) plus, while a relay is actively streaming, the
 * time the current window was opened (open_since).  open_since == 0
 * means no window is currently open.  Intervals are kept in the order
 * they closed (oldest first); by construction (rcv_close's slack) any
 * two of them are separated by at least RCV_CLOSE_SLACK_MS, so a span
 * is covered only when it lies wholly inside ONE interval (or inside
 * the currently open window) -- never by splicing two together.
 *
 * No ircd dependencies: this module is pure and is linked directly into
 * its cmocka suite (ircd/test/chathistory_recv_cmocka.c links the real
 * ../chathistory_recv.o, nothing else).
 */
#ifndef INCLUDED_chathistory_recv_h
#define INCLUDED_chathistory_recv_h

#ifndef INCLUDED_stdint_h
#include <stdint.h>
#define INCLUDED_stdint_h
#endif
#ifndef INCLUDED_stddef_h
#include <stddef.h>
#define INCLUDED_stddef_h
#endif

/** Intervals kept per record.  Oldest dropped first (FIFO) past this. */
#define RCV_MAX 64

/** Backed off from "now" when closing a window: an in-flight relay can
 * still carry origin times stamped before the last PART reached us, so
 * the window's reported end sits this far behind the close event.
 * history.c also opens a window (one that is not a channel's creation) this
 * far AFTER the JOIN: a line stamped after our JOIN but sent before the
 * JOIN reached its sender's server is not routed here.
 * Assumption: an event's propagation and processing between servers takes
 * less than this.  A sender whose main loop stalls for longer (a line
 * stamped, then relayed more than 30 s later) can put a line this server
 * never received inside a window, or one it did receive outside. */
#define RCV_CLOSE_SLACK_MS 30000

/** One closed, completed span.  Epoch ms, inclusive both ends. */
struct rcv_interval {
  int64_t start;
  int64_t end;
};

/** What one peer relationship has received of one channel's history.
 * @a open_since is 0 when no window is currently open. */
struct rcv_record {
  uint8_t count;                  /**< entries used in @a iv */
  int64_t open_since;             /**< 0 = closed */
  struct rcv_interval iv[RCV_MAX];
};

/** The pack format version rcv_pack writes and rcv_unpack accepts. */
#define RCV_PACK_VERSION 1

/** Open a new receive window at @a start_ms.  No-op when a window is
 * already open (does not move its open_since). */
extern void rcv_open(struct rcv_record *r, int64_t start_ms);

/** Close the open window (no-op when none is open).  Its end is
 * @a now_ms minus RCV_CLOSE_SLACK_MS; if that end is before the
 * window's start, the window is dropped (discarded, not recorded) --
 * it was never open long enough to outlive the slack.  Otherwise the
 * completed [start, end] interval is appended, FIFO-dropping iv[0]
 * first if the record is already at RCV_MAX.  Either way, the window
 * is closed (open_since becomes 0). */
extern void rcv_close(struct rcv_record *r, int64_t now_ms);

/** 1 iff [@a lo_ms, @a hi_ms] lies wholly inside exactly one of the
 * closed intervals, or inside [open_since, @a now_ms] while a window is
 * open; 0 otherwise (including a gap straddling two intervals, a span
 * straddling an interval and the open window, or an inverted range --
 * @a lo_ms > @a hi_ms -- which is never "received", whatever bounds it
 * falls between). */
extern int rcv_covers(const struct rcv_record *r, int64_t lo_ms,
                       int64_t hi_ms, int64_t now_ms);

/** Nothing at or before @a upto_ms counts as received any more -- the
 * retention horizon moved (the trim's owner clip, Q1).  A closed
 * interval that ends at or before @a upto_ms is dropped outright; one
 * that straddles it has its start raised to @a upto_ms + 1; one that
 * starts after it is untouched.  If a window is currently open and its
 * open_since is at or before @a upto_ms, open_since is raised to
 * @a upto_ms + 1 as well. */
extern void rcv_clip(struct rcv_record *r, int64_t upto_ms);

/** A record left open across a restart: close it as of @a alive_ms (the
 * last time this server is known to have been running), the same way
 * rcv_close closes against "now". */
extern void rcv_boot_close(struct rcv_record *r, int64_t alive_ms);

/** Serialize @a r into @a buf (capacity @a size): version byte
 * (RCV_PACK_VERSION), count byte, open_since, then @a r->count
 * intervals (start, end) -- every int64 field little-endian, 8 bytes.
 * @return bytes written, or -1 if @a buf is too small for the record. */
extern int rcv_pack(const struct rcv_record *r, unsigned char *buf,
                     size_t size);

/** Parse @a len bytes at @a buf (rcv_pack's format) into @a r.
 * @return 0 on success, -1 if the version is not RCV_PACK_VERSION, the
 * buffer is too short for its own declared count, or the declared count
 * exceeds RCV_MAX. */
extern int rcv_unpack(const unsigned char *buf, size_t len,
                       struct rcv_record *r);

/** The received floor's high-water mark (Push D R40): a store's "rows at or
 * before this may be gone" floor only rises.  Rows deleted under a higher
 * floor stay deleted when retention is raised or set to 0, when the clock
 * steps back, or when the eviction floor is dropped once retention passes
 * it -- so a lower floor never lowers the mark.  Raise *@a hw to @a floor_ms
 * when that is higher -- but never past @a ceil_ms (now, R41): a clock
 * stepped forward or a corrupt key would otherwise put the mark ahead of
 * every row and keep it there.  A mark already past @a ceil_ms comes down
 * to it.  *@a capped (when not NULL) says whether the ceiling cut it.
 * @return The effective floor: *@a hw after the raise (the floor itself,
 * capped, when @a hw is NULL). */
extern int64_t rcv_floor_raise(int64_t *hw, int64_t floor_ms, int64_t ceil_ms,
                               int *capped);

/** A meta row's value (the windows' heartbeat, the high-water floor):
 * @a ms as 8 little-endian bytes into @a out. */
extern void rcv_ms_pack(int64_t ms, unsigned char out[8]);

/** Parse a meta row's value: exactly 8 little-endian bytes.
 * @return 0 with *@a ms set, or -1 (NULL, or not 8 bytes; *@a ms
 * untouched). */
extern int rcv_ms_unpack(const unsigned char *buf, size_t len, int64_t *ms);

#endif /* INCLUDED_chathistory_recv_h */
