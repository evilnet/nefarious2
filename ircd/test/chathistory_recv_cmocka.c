/* cmocka suite for receive windows (include/chathistory_recv.h, W5 Task
 * 8): what a peer relationship has already received of one channel's
 * history federation, so a later request only pulls the gap.  Pure
 * module; links the REAL ../chathistory_recv.o only, no test_stub.o.
 *
 * Every scenario below is built so that any two closed intervals in
 * play are separated by far more than RCV_CLOSE_SLACK_MS (30000ms), per
 * the header's comment: containment in exactly one interval is the
 * whole test, never a splice across two.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "chathistory_recv.h"

static void test_rcv_open_covers(void **state)
{
  struct rcv_record r;
  (void)state;

  memset(&r, 0, sizeof(r));
  rcv_open(&r, 1000);

  assert_int_equal(rcv_covers(&r, 2000, 5000, 6000), 1);
  assert_int_equal(rcv_covers(&r, 500, 2000, 6000), 0);
}

static void test_rcv_covers_inverted_range_is_never_covered(void **state)
{
  struct rcv_record r;
  (void)state;

  memset(&r, 0, sizeof(r));
  rcv_open(&r, 1000);

  /* lo > hi: an inverted range is never "received", even though lo and
   * hi independently satisfy the open window's bounds on their own. */
  assert_int_equal(rcv_covers(&r, 5000, 2000, 6000), 0);

  rcv_close(&r, 100000);                /* interval: [1000, 70000] */
  assert_int_equal(rcv_covers(&r, 60000, 10000, 999999), 0);
}

static void test_rcv_close_slack(void **state)
{
  struct rcv_record r;
  (void)state;

  memset(&r, 0, sizeof(r));
  rcv_open(&r, 1000);
  rcv_close(&r, 100000);              /* end = 100000 - 30000 = 70000 */

  assert_int_equal(r.count, 1);
  assert_int_equal(r.open_since, 0);
  assert_int_equal(rcv_covers(&r, 60000, 69000, 100000), 1);
  assert_int_equal(rcv_covers(&r, 60000, 80000, 100000), 0);
}

static void test_rcv_short_interval_dropped(void **state)
{
  struct rcv_record r;
  (void)state;

  memset(&r, 0, sizeof(r));
  rcv_open(&r, 1000);
  rcv_close(&r, 20000);               /* end = 20000 - 30000 = -10000 < start */

  assert_int_equal(r.count, 0);
  assert_int_equal(r.open_since, 0);   /* the window still closed */
}

static void test_rcv_close_on_closed_is_noop(void **state)
{
  struct rcv_record r;
  (void)state;

  memset(&r, 0, sizeof(r));
  /* never opened: open_since is already 0 */
  rcv_close(&r, 100000);

  assert_int_equal(r.count, 0);
  assert_int_equal(r.open_since, 0);
}

static void test_rcv_gap_not_covered(void **state)
{
  struct rcv_record r;
  (void)state;

  memset(&r, 0, sizeof(r));
  rcv_open(&r, 1000);
  rcv_close(&r, 50000);                /* interval 1: [1000, 20000] */
  rcv_open(&r, 100000);
  rcv_close(&r, 150000);               /* interval 2: [100000, 120000] */

  assert_int_equal(r.count, 2);
  /* A span inside interval 1 and inside interval 2 is covered singly. */
  assert_int_equal(rcv_covers(&r, 1000, 20000, 999999), 1);
  assert_int_equal(rcv_covers(&r, 100000, 120000, 999999), 1);
  /* A span across the gap between them is covered by neither alone. */
  assert_int_equal(rcv_covers(&r, 15000, 110000, 999999), 0);
}

static void test_rcv_fifo(void **state)
{
  struct rcv_record r;
  int i;
  int64_t oldest_start, oldest_end;
  (void)state;

  memset(&r, 0, sizeof(r));
  for (i = 0; i < 65; i++) {
    int64_t open_ms = (int64_t)i * 100000 + 1000;
    int64_t close_ms = open_ms + 50000;    /* end = open_ms + 20000 */

    if (i == 0) {
      oldest_start = open_ms;
      oldest_end = close_ms - RCV_CLOSE_SLACK_MS;
    }
    rcv_open(&r, open_ms);
    rcv_close(&r, close_ms);
  }

  assert_int_equal(r.count, RCV_MAX);
  assert_int_equal(rcv_covers(&r, oldest_start, oldest_end, 999999999), 0);
  /* the newest (cycle 64) is still there */
  assert_int_equal(rcv_covers(&r, (int64_t)64 * 100000 + 1000,
                               (int64_t)64 * 100000 + 1000 + 50000 - RCV_CLOSE_SLACK_MS,
                               999999999), 1);
}

static void test_rcv_clip(void **state)
{
  struct rcv_record r;
  (void)state;

  memset(&r, 0, sizeof(r));
  rcv_open(&r, 1000);
  rcv_close(&r, 100000);               /* interval: [1000, 70000] */
  assert_int_equal(r.count, 1);

  rcv_clip(&r, 50000);
  assert_int_equal(rcv_covers(&r, 40000, 60000, 999999), 0);
  assert_int_equal(rcv_covers(&r, 50001, 60000, 999999), 1);

  rcv_clip(&r, 80000);
  assert_int_equal(r.count, 0);
}

static void test_rcv_clip_open(void **state)
{
  struct rcv_record r;
  (void)state;

  memset(&r, 0, sizeof(r));
  rcv_open(&r, 1000);
  rcv_clip(&r, 5000);

  assert_int_equal(r.open_since, 5001);
  assert_int_equal(rcv_covers(&r, 2000, 6000, 9000), 0);
  assert_int_equal(rcv_covers(&r, 5001, 6000, 9000), 1);
}

static void test_rcv_clip_open_future_unchanged(void **state)
{
  struct rcv_record r;
  (void)state;

  memset(&r, 0, sizeof(r));
  rcv_open(&r, 9999);
  rcv_clip(&r, 5000);                  /* floor is before open_since: no-op on it */

  assert_int_equal(r.open_since, 9999);
}

static void test_rcv_boot_close(void **state)
{
  struct rcv_record r;
  (void)state;

  memset(&r, 0, sizeof(r));
  rcv_open(&r, 1000);
  rcv_boot_close(&r, 200000);          /* end = 200000 - 30000 = 170000 */

  assert_int_equal(r.open_since, 0);
  assert_int_equal(rcv_covers(&r, 150000, 169000, 999999), 1);
  assert_int_equal(rcv_covers(&r, 150000, 199000, 999999), 0);
}

static void test_rcv_open_idempotent(void **state)
{
  struct rcv_record r;
  (void)state;

  memset(&r, 0, sizeof(r));
  rcv_open(&r, 1000);
  rcv_open(&r, 5000);                  /* no-op: already open */

  assert_int_equal(r.open_since, 1000);
}

static void test_rcv_pack_roundtrip(void **state)
{
  struct rcv_record in, out;
  unsigned char buf[2 + 8 + RCV_MAX * 16];
  int n;
  (void)state;

  memset(&in, 0, sizeof(in));
  in.count = 3;
  in.iv[0].start = 1000;    in.iv[0].end = 2000;
  in.iv[1].start = 5000;    in.iv[1].end = 6000;
  in.iv[2].start = 9000;    in.iv[2].end = 9500;
  in.open_since = 20000;    /* a window is also currently open */

  n = rcv_pack(&in, buf, sizeof(buf));
  assert_true(n > 0);

  memset(&out, 0xff, sizeof(out));
  assert_int_equal(rcv_unpack(buf, (size_t)n, &out), 0);

  assert_int_equal(out.count, in.count);
  assert_int_equal(out.open_since, in.open_since);
  assert_int_equal(out.iv[0].start, in.iv[0].start);
  assert_int_equal(out.iv[0].end, in.iv[0].end);
  assert_int_equal(out.iv[1].start, in.iv[1].start);
  assert_int_equal(out.iv[1].end, in.iv[1].end);
  assert_int_equal(out.iv[2].start, in.iv[2].start);
  assert_int_equal(out.iv[2].end, in.iv[2].end);
}

static void test_rcv_unpack_rejects(void **state)
{
  struct rcv_record in, out;
  unsigned char buf[2 + 8 + RCV_MAX * 16];
  int n;
  (void)state;

  memset(&in, 0, sizeof(in));
  in.count = 1;
  in.iv[0].start = 1;
  in.iv[0].end = 2;
  in.open_since = 0;

  n = rcv_pack(&in, buf, sizeof(buf));
  assert_true(n > 0);

  buf[0] = 2;                          /* unknown version */
  assert_int_equal(rcv_unpack(buf, (size_t)n, &out), -1);

  buf[0] = RCV_PACK_VERSION;
  assert_int_equal(rcv_unpack(buf, (size_t)(n - 1), &out), -1);  /* short */
}

/* Fix round 1, IMPORTANT: test_rcv_pack_roundtrip alone cannot catch a
 * byte-order regression (e.g. swapping rcv_pack/rcv_unpack's body for
 * a host-native memcpy of the struct) because it round-trips through
 * the SAME host, which would still agree with itself. This test packs
 * a record with distinct, non-palindromic bytes in every field and
 * checks the exact byte layout at known offsets: version, count, then
 * little-endian open_since, then little-endian start/end -- a layout
 * only the documented wire format produces, not whatever the host's
 * struct padding/endianness happen to be. */
static void test_rcv_pack_exact_bytes(void **state)
{
  struct rcv_record in;
  unsigned char buf[2 + 8 + 16];
  int n;
  (void)state;

  memset(&in, 0, sizeof(in));
  in.count = 1;
  in.open_since  = (int64_t)0x0102030405060708LL;
  in.iv[0].start = (int64_t)0x1112131415161718LL;
  in.iv[0].end   = (int64_t)0x2122232425262728LL;

  n = rcv_pack(&in, buf, sizeof(buf));
  assert_int_equal(n, (int)sizeof(buf));

  assert_int_equal(buf[0], RCV_PACK_VERSION);
  assert_int_equal(buf[1], 1);

  /* open_since = 0x0102030405060708, little-endian: least-significant
   * byte (0x08) first. */
  assert_int_equal(buf[2], 0x08); assert_int_equal(buf[3], 0x07);
  assert_int_equal(buf[4], 0x06); assert_int_equal(buf[5], 0x05);
  assert_int_equal(buf[6], 0x04); assert_int_equal(buf[7], 0x03);
  assert_int_equal(buf[8], 0x02); assert_int_equal(buf[9], 0x01);

  /* iv[0].start = 0x1112131415161718, little-endian. */
  assert_int_equal(buf[10], 0x18); assert_int_equal(buf[11], 0x17);
  assert_int_equal(buf[12], 0x16); assert_int_equal(buf[13], 0x15);
  assert_int_equal(buf[14], 0x14); assert_int_equal(buf[15], 0x13);
  assert_int_equal(buf[16], 0x12); assert_int_equal(buf[17], 0x11);

  /* iv[0].end = 0x2122232425262728, little-endian. */
  assert_int_equal(buf[18], 0x28); assert_int_equal(buf[19], 0x27);
  assert_int_equal(buf[20], 0x26); assert_int_equal(buf[21], 0x25);
  assert_int_equal(buf[22], 0x24); assert_int_equal(buf[23], 0x23);
  assert_int_equal(buf[24], 0x22); assert_int_equal(buf[25], 0x21);
}

/* The other half of the byte-order regression check: a buffer built
 * by hand (not via rcv_pack) decodes to the values its bytes spell out
 * in little-endian, not whatever a host-native read would give. */
static void test_rcv_unpack_hand_built(void **state)
{
  unsigned char buf[2 + 8 + 16] = {
    RCV_PACK_VERSION, 1,
    0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,  /* open_since */
    0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,  /* iv[0].start */
    0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,  /* iv[0].end */
  };
  struct rcv_record out;
  (void)state;

  memset(&out, 0xff, sizeof(out));
  assert_int_equal(rcv_unpack(buf, sizeof(buf), &out), 0);

  assert_int_equal(out.count, 1);
  assert_true(out.open_since  == (int64_t)0x0102030405060708LL);
  assert_true(out.iv[0].start == (int64_t)0x1112131415161718LL);
  assert_true(out.iv[0].end   == (int64_t)0x2122232425262728LL);
}

/* Fix round 1, Minor: a declared count over RCV_MAX is refused even
 * when the buffer is otherwise long enough for that (bogus) count. */
static void test_rcv_unpack_rejects_count_over_max(void **state)
{
  unsigned char buf[2 + 8 + (RCV_MAX + 1) * 16];
  struct rcv_record out;
  (void)state;

  memset(buf, 0, sizeof(buf));
  buf[0] = RCV_PACK_VERSION;
  buf[1] = RCV_MAX + 1;                /* one more than the cap */

  assert_int_equal(rcv_unpack(buf, sizeof(buf), &out), -1);
}

/* Fix round 1, Minor: pack/unpack at a buffer size exactly at the
 * limit succeeds; one byte short fails on both sides. */
static void test_rcv_pack_unpack_size_boundary(void **state)
{
  struct rcv_record in, out;
  unsigned char buf[2 + 8 + 16];
  int n;
  (void)state;

  memset(&in, 0, sizeof(in));
  in.count = 1;
  in.iv[0].start = 1;
  in.iv[0].end = 2;

  assert_int_equal(rcv_pack(&in, buf, sizeof(buf)), (int)sizeof(buf));
  assert_int_equal(rcv_pack(&in, buf, sizeof(buf) - 1), -1);

  n = rcv_pack(&in, buf, sizeof(buf));
  assert_int_equal(n, (int)sizeof(buf));
  assert_int_equal(rcv_unpack(buf, (size_t)n, &out), 0);
  assert_int_equal(rcv_unpack(buf, (size_t)n - 1, &out), -1);
}

/* The received floor's high-water mark (Push D R40): it only rises.  A
 * lower floor -- retention raised or set to 0, the clock stepped back, an
 * eviction floor dropped once retention passes it -- never lowers it, and
 * the effective floor is always the high-water mark. */
static void test_rcv_floor_raise_only_rises(void **state)
{
  const int64_t now = 1800000000000LL;
  int64_t hw = 0;
  int capped = -1;
  (void)state;

  assert_int_equal(rcv_floor_raise(&hw, 1000, now, &capped), 1000);
  assert_int_equal(hw, 1000);
  assert_int_equal(capped, 0);
  assert_int_equal(rcv_floor_raise(&hw, 400, now, &capped), 1000);    /* retention raised */
  assert_int_equal(hw, 1000);
  assert_int_equal(rcv_floor_raise(&hw, 0, now, NULL), 1000);         /* retention 0, no eviction */
  assert_int_equal(hw, 1000);
  assert_int_equal(rcv_floor_raise(&hw, 1000, now, NULL), 1000);
  assert_int_equal(rcv_floor_raise(&hw, 1700000000123LL, now, &capped), 1700000000123LL);
  assert_int_equal(hw, 1700000000123LL);
  assert_int_equal(capped, 0);
  assert_int_equal(rcv_floor_raise(NULL, 5, now, NULL), 5);           /* no mark: the floor itself */
}

/* The mark never passes now (R41): a clock stepped forward, or a corrupt
 * or future key, would otherwise put it ahead of every row and keep it
 * there across restarts.  A floor past now is cut to now; a mark already
 * past now (a loaded key) comes down to now; both say they capped.  Below
 * now nothing is capped, a floor equal to now included. */
static void test_rcv_floor_raise_capped_at_now(void **state)
{
  const int64_t now = 1800000000000LL;
  int64_t hw = 1000;
  int capped = 0;
  (void)state;

  assert_int_equal(rcv_floor_raise(&hw, now + 86400000LL, now, &capped), now);
  assert_int_equal(hw, now);
  assert_int_equal(capped, 1);
  /* Time moves on: the mark stays where it was cut, nothing capped. */
  assert_int_equal(rcv_floor_raise(&hw, 2000, now + 5000, &capped), now);
  assert_int_equal(capped, 0);

  hw = now + 3600000LL;                                   /* a key from the future */
  assert_int_equal(rcv_floor_raise(&hw, 0, now, &capped), now);
  assert_int_equal(hw, now);
  assert_int_equal(capped, 1);

  hw = 0;
  assert_int_equal(rcv_floor_raise(&hw, now, now, &capped), now);    /* at now: not capped */
  assert_int_equal(capped, 0);
  assert_int_equal(rcv_floor_raise(NULL, now + 1, now, &capped), now);
  assert_int_equal(capped, 1);
}

/* The meta rows' 8-byte value (the heartbeat's, the floor's): epoch ms,
 * little-endian, exactly 8 bytes -- the byte order the heartbeat has
 * always been written in. */
static void test_rcv_ms_pack(void **state)
{
  unsigned char b[8];
  static const unsigned char want[8] = { 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
  int64_t ms = 0;
  (void)state;

  rcv_ms_pack(0x0102030405060708LL, b);
  assert_memory_equal(b, want, 8);
  assert_int_equal(rcv_ms_unpack(b, 8, &ms), 0);
  assert_int_equal(ms, 0x0102030405060708LL);
  rcv_ms_pack(1700000000123LL, b);
  assert_int_equal(rcv_ms_unpack(b, 8, &ms), 0);
  assert_int_equal(ms, 1700000000123LL);
  ms = 42;
  assert_int_equal(rcv_ms_unpack(b, 7, &ms), -1);
  assert_int_equal(rcv_ms_unpack(b, 9, &ms), -1);
  assert_int_equal(rcv_ms_unpack(NULL, 8, &ms), -1);
  assert_int_equal(ms, 42);                              /* untouched on a reject */
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_rcv_open_covers),
    cmocka_unit_test(test_rcv_covers_inverted_range_is_never_covered),
    cmocka_unit_test(test_rcv_close_slack),
    cmocka_unit_test(test_rcv_short_interval_dropped),
    cmocka_unit_test(test_rcv_close_on_closed_is_noop),
    cmocka_unit_test(test_rcv_gap_not_covered),
    cmocka_unit_test(test_rcv_fifo),
    cmocka_unit_test(test_rcv_clip),
    cmocka_unit_test(test_rcv_clip_open),
    cmocka_unit_test(test_rcv_clip_open_future_unchanged),
    cmocka_unit_test(test_rcv_boot_close),
    cmocka_unit_test(test_rcv_open_idempotent),
    cmocka_unit_test(test_rcv_pack_roundtrip),
    cmocka_unit_test(test_rcv_unpack_rejects),
    cmocka_unit_test(test_rcv_pack_exact_bytes),
    cmocka_unit_test(test_rcv_unpack_hand_built),
    cmocka_unit_test(test_rcv_unpack_rejects_count_over_max),
    cmocka_unit_test(test_rcv_pack_unpack_size_boundary),
    cmocka_unit_test(test_rcv_floor_raise_only_rises),
    cmocka_unit_test(test_rcv_floor_raise_capped_at_now),
    cmocka_unit_test(test_rcv_ms_pack),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
