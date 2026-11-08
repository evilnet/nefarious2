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

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_rcv_open_covers),
    cmocka_unit_test(test_rcv_close_slack),
    cmocka_unit_test(test_rcv_short_interval_dropped),
    cmocka_unit_test(test_rcv_gap_not_covered),
    cmocka_unit_test(test_rcv_fifo),
    cmocka_unit_test(test_rcv_clip),
    cmocka_unit_test(test_rcv_clip_open),
    cmocka_unit_test(test_rcv_boot_close),
    cmocka_unit_test(test_rcv_open_idempotent),
    cmocka_unit_test(test_rcv_pack_roundtrip),
    cmocka_unit_test(test_rcv_unpack_rejects),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
