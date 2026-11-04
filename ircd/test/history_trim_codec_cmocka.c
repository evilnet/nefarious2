/* history_trim_codec_cmocka.c - unit tests for ircd/history_trim_codec.c.
 *
 * Pure codec: no database, no running ircd. Byte layouts for the
 * messages / msgid_index / reply_index keys are proven against
 * hand-built expected bytes matching history.c's build_key /
 * build_msgid_index_key / build_reply_index_key (this suite cannot
 * link history.c itself -- its builders are static and the module is
 * not pure). The by_time / by_owner index codecs are this project's
 * own new encodings.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <cmocka.h>
#include <netinet/in.h>

#include "res.h"
#include "history_trim_codec.h"

/* Build a struct irc_in_addr from 8 HOST-order 16-bit words, converting
 * each to network order on the way in -- same convention as
 * ircd_in_addr_t.c's address_test fixtures. */
static void mkaddr(struct irc_in_addr *a,
                    unsigned short w0, unsigned short w1,
                    unsigned short w2, unsigned short w3,
                    unsigned short w4, unsigned short w5,
                    unsigned short w6, unsigned short w7)
{
  a->in6_16[0] = htons(w0);
  a->in6_16[1] = htons(w1);
  a->in6_16[2] = htons(w2);
  a->in6_16[3] = htons(w3);
  a->in6_16[4] = htons(w4);
  a->in6_16[5] = htons(w5);
  a->in6_16[6] = htons(w6);
  a->in6_16[7] = htons(w7);
}

/* RocksDB's default bytewise comparator: compare the shared prefix,
 * then the shorter key sorts first on a tie. */
static int keycmp(const void *a, size_t alen, const void *b, size_t blen)
{
  size_t n = alen < blen ? alen : blen;
  int c = n ? memcmp(a, b, n) : 0;
  if (c) return c;
  if (alen < blen) return -1;
  if (alen > blen) return 1;
  return 0;
}

static void test_parse_ms(void **state)
{
  (void)state;
  assert_int_equal(htc_parse_ms("1700000000.123"), 1700000000123ULL);
  assert_int_equal(htc_parse_ms("1700000000.5"), 1700000000500ULL);
  assert_int_equal(htc_parse_ms("1700000000"), 1700000000000ULL);
  assert_int_equal(htc_parse_ms(""), 0ULL);
  assert_int_equal(htc_parse_ms("abc"), 0ULL);
  assert_int_equal(htc_parse_ms(NULL), 0ULL);
}

static void test_owner_account(void **state)
{
  struct irc_in_addr ip;
  char b[HTC_OWNER_MAX];
  int n;
  (void)state;
  mkaddr(&ip, 0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201);
  n = htc_owner_key(b, sizeof(b), "Bob", &ip, "leaf.example");
  assert_int_equal(n, 5);
  assert_string_equal(b, "a:bob");
}

static void test_owner_star(void **state)
{
  char b[HTC_OWNER_MAX];
  int n;
  (void)state;
  n = htc_owner_key(b, sizeof(b), "*", NULL, NULL);
  assert_int_equal(n, 1);
  assert_string_equal(b, "-");
}

static void test_owner_ipv4(void **state)
{
  struct irc_in_addr ip;
  char b[HTC_OWNER_MAX];
  int n;
  (void)state;
  mkaddr(&ip, 0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201);
  n = htc_owner_key(b, sizeof(b), "", &ip, "leaf.example");
  assert_int_equal(n, 10);
  assert_string_equal(b, "i:c0000201");
}

static void test_owner_ipv6_64(void **state)
{
  struct irc_in_addr ip1, ip2;
  char b[HTC_OWNER_MAX];
  int n;
  (void)state;

  mkaddr(&ip1, 0x2001, 0x0db8, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006);
  n = htc_owner_key(b, sizeof(b), "", &ip1, NULL);
  assert_int_equal(n, 18);
  assert_string_equal(b, "i:20010db800010002");

  mkaddr(&ip2, 0x2001, 0x0db8, 0x0001, 0x0002, 0xffff, 0, 0, 0x0009);
  n = htc_owner_key(b, sizeof(b), "", &ip2, NULL);
  assert_int_equal(n, 18);
  assert_string_equal(b, "i:20010db800010002");
}

static void test_owner_unspec_ip(void **state)
{
  struct irc_in_addr ip;
  char b[HTC_OWNER_MAX];
  int n;
  (void)state;
  /* ::ffff:0.0.0.0 -- the IPv4-mapped unspecified address */
  mkaddr(&ip, 0, 0, 0, 0, 0, 0xffff, 0, 0);
  n = htc_owner_key(b, sizeof(b), "", &ip, "X3.Example");
  assert_int_equal(n, 12);
  assert_string_equal(b, "s:x3.example");
}

static void test_owner_none(void **state)
{
  char b[HTC_OWNER_MAX];
  int n;
  (void)state;
  n = htc_owner_key(b, sizeof(b), NULL, NULL, NULL);
  assert_int_equal(n, 1);
  assert_string_equal(b, "-");
}

static void test_owner_overflow(void **state)
{
  char b[4];
  (void)state;
  assert_int_equal(htc_owner_key(b, sizeof(b), "bob", NULL, NULL), -1);
}

static void test_msg_key(void **state)
{
  char b[HTC_MSG_KEY_MAX];
  int n;
  (void)state;

  n = htc_msg_key(b, sizeof(b), "#Chan", "1700000000.123", "M1");
  assert_int_equal(n, 23);
  assert_memory_equal(b, "#chan\0" "1700000000.123\0" "M1", 23);

  n = htc_msg_key(b, sizeof(b), "#Chan", "1700000000.123", "");
  assert_int_equal(n, 21);
  assert_memory_equal(b, "#chan\0" "1700000000.123\0", 21);
}

static void test_msg_key_parse(void **state)
{
  char b[HTC_MSG_KEY_MAX];
  char target[HTC_TARGET_MAX], ts[HTC_TS_MAX], msgid[HTC_MSGID_MAX];
  int n, rc;
  (void)state;

  n = htc_msg_key(b, sizeof(b), "#Chan", "1700000000.123", "M1");
  rc = htc_msg_key_parse(b, (size_t)n, target, sizeof(target),
                          ts, sizeof(ts), msgid, sizeof(msgid));
  assert_int_equal(rc, 0);
  assert_string_equal(target, "#chan");
  assert_string_equal(ts, "1700000000.123");
  assert_string_equal(msgid, "M1");
}

static void test_bt_key_order(void **state)
{
  char b1[HTC_BT_KEY_MAX], b2[HTC_BT_KEY_MAX], b3[HTC_BT_KEY_MAX];
  char b4[HTC_BT_KEY_MAX], b5[HTC_BT_KEY_MAX];
  int n1, n2, n3, n4, n5;
  (void)state;

  n1 = htc_bt_key(b1, sizeof(b1), 1000, "#b", "M1");
  n2 = htc_bt_key(b2, sizeof(b2), 1000, "#c", "M0");
  n3 = htc_bt_key(b3, sizeof(b3), 1001, "#a", "M0");
  assert_true(keycmp(b1, (size_t)n1, b2, (size_t)n2) < 0);
  assert_true(keycmp(b2, (size_t)n2, b3, (size_t)n3) < 0);

  n4 = htc_bt_key(b4, sizeof(b4), 1000, "#ChAn", "M1");
  n5 = htc_bt_key(b5, sizeof(b5), 1000, "#chan", "M1");
  assert_int_equal(n4, n5);
  assert_memory_equal(b4, b5, (size_t)n4);
}

static void test_bt_key_roundtrip(void **state)
{
  char buf[HTC_BT_KEY_MAX];
  char target[HTC_TARGET_MAX], msgid[HTC_MSGID_MAX];
  uint64_t ms;
  int n, rc;
  (void)state;

  n = htc_bt_key(buf, sizeof(buf), 1700000000123ULL, "#chan", "AAx");
  rc = htc_bt_key_parse(buf, (size_t)n, &ms, target, sizeof(target),
                         msgid, sizeof(msgid));
  assert_int_equal(rc, 0);
  assert_int_equal(ms, 1700000000123ULL);
  assert_string_equal(target, "#chan");
  assert_string_equal(msgid, "AAx");

  n = htc_bt_key(buf, sizeof(buf), 1700000000123ULL, "#chan", "");
  assert_int_equal(n, 8 + 5 + 1);
}

static void test_bt_be64_bound(void **state)
{
  unsigned char o[8];
  char bprev[HTC_BT_KEY_MAX], bsame[HTC_BT_KEY_MAX];
  int nprev, nsame;
  (void)state;

  htc_be64(o, 1500);

  nprev = htc_bt_key(bprev, sizeof(bprev), 1499, "#x", "m");
  (void)nprev;
  assert_true(memcmp(o, bprev, 8) > 0);

  nsame = htc_bt_key(bsame, sizeof(bsame), 1500, "#x", "m");
  assert_true(keycmp(o, 8, bsame, (size_t)nsame) < 0);
}

static void test_bo_key_split(void **state)
{
  char bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX];
  char owner_out[HTC_OWNER_MAX];
  const void *bt_out;
  size_t bt_outlen;
  int btlen, bolen, rc;
  (void)state;

  btlen = htc_bt_key(bt, sizeof(bt), 1000, "#chan", "M1");
  bolen = htc_bo_key(bo, sizeof(bo), "a:bob", bt, (size_t)btlen);
  assert_true(bolen > 0);

  rc = htc_bo_split(bo, (size_t)bolen, owner_out, sizeof(owner_out),
                     &bt_out, &bt_outlen);
  assert_int_equal(rc, 0);
  assert_string_equal(owner_out, "a:bob");
  assert_int_equal((int)bt_outlen, btlen);
  assert_memory_equal(bt_out, bt, (size_t)btlen);
}

static void test_bo_prefix_isolates(void **state)
{
  char prefix[HTC_OWNER_MAX];
  char bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX];
  int plen, btlen, bolen;
  (void)state;

  plen = htc_bo_prefix(prefix, sizeof(prefix), "a:bob");
  assert_int_equal(plen, 6);

  btlen = htc_bt_key(bt, sizeof(bt), 1000, "#chan", "M1");
  bolen = htc_bo_key(bo, sizeof(bo), "a:bobby", bt, (size_t)btlen);
  assert_true(bolen > plen);
  assert_true(memcmp(prefix, bo, (size_t)plen) != 0);
}

static void test_rec_roundtrip(void **state)
{
  struct htc_rec r, out;
  char buf[HTC_REC_MAX];
  int n;
  (void)state;

  memset(&r, 0, sizeof(r));
  r.bytes = 4242;
  r.flags = HTC_F_REDACT | HTC_F_ML;
  strcpy(r.ts, "1700000000.123");
  strcpy(r.owner, "i:c0000201");
  r.reply_parent[0] = '\0';
  strcpy(r.redact_parent, "PARENT1");

  n = htc_rec_pack(buf, sizeof(buf), &r);
  assert_true(n > 0);

  memset(&out, 0, sizeof(out));
  assert_int_equal(htc_rec_parse(buf, (size_t)n, &out), 0);
  assert_int_equal(out.bytes, 4242);
  assert_int_equal(out.flags, HTC_F_REDACT | HTC_F_ML);
  assert_string_equal(out.ts, "1700000000.123");
  assert_string_equal(out.owner, "i:c0000201");
  assert_string_equal(out.reply_parent, "");
  assert_string_equal(out.redact_parent, "PARENT1");
}

static void test_rec_parse_rejects(void **state)
{
  struct htc_rec out;
  unsigned char v2[6] = { 2, 0, 0, 0, 0, 0 };
  unsigned char short5[5] = { 1, 0, 0, 0, 0 };
  unsigned char only2[6 + 5];
  unsigned char tail[5];
  (void)state;

  assert_int_equal(htc_rec_parse(v2, sizeof(v2), &out), -1);
  assert_int_equal(htc_rec_parse(short5, sizeof(short5), &out), -1);

  only2[0] = 1;
  only2[1] = 0;
  htc_size_pack(only2 + 2, 0);
  tail[0] = 'a'; tail[1] = '\0'; tail[2] = 'b'; tail[3] = '\0'; tail[4] = 'c';
  memcpy(only2 + 6, tail, 5);
  assert_int_equal(htc_rec_parse(only2, sizeof(only2), &out), -1);
}

static void test_size_pack(void **state)
{
  unsigned char o[4];
  uint32_t v;
  (void)state;

  htc_size_pack(o, 0x01020304u);
  assert_int_equal(o[0], 1);
  assert_int_equal(o[1], 2);
  assert_int_equal(o[2], 3);
  assert_int_equal(o[3], 4);

  assert_int_equal(htc_size_parse(o, 4, &v), 0);
  assert_int_equal(v, 0x01020304u);

  assert_int_equal(htc_size_parse(o, 3, &v), -1);
}

static void test_row_bytes(void **state)
{
  (void)state;
  assert_int_equal(htc_row_bytes(40, 100, 0, 30, 6), 255u);
  assert_int_equal(htc_row_bytes(40, 100, 4000, 30, 6), 4255u);
  assert_int_equal(htc_row_bytes(SIZE_MAX / 2, SIZE_MAX / 2, 0, 0, 0),
                    (uint32_t)UINT32_MAX);
}

/* ---- Amendment (pre-flight 2026-11-04): msgid-index and reply-index
 * key builders, byte-identical to history.c's build_msgid_index_key
 * and build_reply_index_key. ---- */

static void test_msgid_key(void **state)
{
  char b[HTC_MSGID_MAX + 1 + HTC_TARGET_MAX];
  int n;
  (void)state;

  n = htc_msgid_key(b, sizeof(b), "M1", "#Chan");
  assert_int_equal(n, 8);
  assert_memory_equal(b, "M1\0#chan", 8);
}

static void test_reply_child_key(void **state)
{
  char b[HTC_TARGET_MAX + HTC_MSGID_MAX + HTC_TS_MAX + HTC_MSGID_MAX];
  int n;
  (void)state;

  n = htc_reply_child_key(b, sizeof(b), "#Chan", "PARENT1",
                           "1700000000.123", "M1");
  assert_int_equal(n, 31);
  assert_memory_equal(b, "#chan\0" "PARENT1\0" "1700000000.123\0" "M1", 31);
}

/* ---- Task 7 (Task 5 review M1): the children-of-a-parent scan prefix,
 * byte-identical to the head of every child key, and to history.c's
 * old hand-built fold(target) \0 parent \0. ---- */

static void test_reply_prefix(void **state)
{
  char b[HTC_TARGET_MAX + HTC_MSGID_MAX + 2];
  char c[HTC_TARGET_MAX + HTC_MSGID_MAX + HTC_TS_MAX + HTC_MSGID_MAX];
  int n, m;
  (void)state;

  n = htc_reply_prefix(b, sizeof(b), "#Chan", "PARENT1");
  assert_int_equal(n, 14);
  assert_memory_equal(b, "#chan\0" "PARENT1\0", 14);
  m = htc_reply_child_key(c, sizeof(c), "#Chan", "PARENT1", "1700000000.123", "M1");
  assert_true(m > n);
  assert_memory_equal(c, b, (size_t)n);
  /* A parent that is a prefix of another is still isolated by its \0. */
  m = htc_reply_child_key(c, sizeof(c), "#Chan", "PARENT10", "1700000000.123", "M1");
  assert_true(memcmp(c, b, (size_t)n) != 0);

  /* The buffer bounds, as the old builder: each part needs its byte of
   * separator. */
  assert_int_equal(htc_reply_prefix(b, 14, "#Chan", "PARENT1"), 14);
  assert_int_equal(htc_reply_prefix(b, 13, "#Chan", "PARENT1"), -1);
  assert_int_equal(htc_reply_prefix(b, 5, "#Chan", "PARENT1"), -1);
  assert_int_equal(htc_reply_prefix(NULL, sizeof(b), "#Chan", "PARENT1"), -1);
  assert_int_equal(htc_reply_prefix(b, sizeof(b), NULL, "PARENT1"), -1);
  assert_int_equal(htc_reply_prefix(b, sizeof(b), "#Chan", NULL), -1);
}

/* ---- Task 3: owner accounting table, the fair-eviction planner,
 * effective coverage days. ---- */

static void test_acct_add_sub(void **state)
{
  struct htc_acct *a = htc_acct_new();
  (void)state;

  htc_acct_add(a, "a:x", 100);
  assert_int_equal(htc_acct_owner(a, "a:x"), 100u);
  assert_int_equal(htc_acct_total(a), 100u);
  assert_int_equal(htc_acct_count(a), 1u);

  htc_acct_add(a, "a:x", -40);
  assert_int_equal(htc_acct_owner(a, "a:x"), 60u);
  assert_int_equal(htc_acct_total(a), 60u);
  assert_int_equal(htc_acct_count(a), 1u);

  htc_acct_add(a, "a:x", -60);
  assert_int_equal(htc_acct_owner(a, "a:x"), 0u);
  assert_int_equal(htc_acct_total(a), 0u);
  assert_int_equal(htc_acct_count(a), 0u);

  htc_acct_free(a);
}

static void test_acct_clamps(void **state)
{
  struct htc_acct *a = htc_acct_new();
  (void)state;

  htc_acct_add(a, "a:y", -10);
  assert_int_equal(htc_acct_count(a), 0u);
  assert_int_equal(htc_acct_total(a), 0u);

  htc_acct_free(a);
}

static void test_acct_top(void **state)
{
  struct htc_acct *a = htc_acct_new();
  struct htc_owner_total top[2];
  size_t n;
  (void)state;

  htc_acct_add(a, "a:p", 10);
  htc_acct_add(a, "a:q", 50);
  htc_acct_add(a, "a:r", 30);

  n = htc_acct_top(a, top, 2);
  assert_int_equal((int)n, 2);
  assert_string_equal(top[0].owner, "a:q");
  assert_int_equal(top[0].bytes, 50u);
  assert_string_equal(top[1].owner, "a:r");
  assert_int_equal(top[1].bytes, 30u);

  htc_acct_free(a);
}

static void test_acct_many(void **state)
{
  struct htc_acct *a = htc_acct_new();
  char owner[16];
  unsigned i;
  (void)state;

  for (i = 0; i < 10000; i++) {
    snprintf(owner, sizeof(owner), "i:%08x", i);
    htc_acct_add(a, owner, 3);
  }

  assert_int_equal((int)htc_acct_count(a), 10000);
  assert_int_equal(htc_acct_total(a), 30000u);

  htc_acct_free(a);
}

/* Default planner params for the tests below: cap 1000, high 85,
 * low 75, quota on, share 10% (share == 100). Tests that need a
 * different knob copy this and override just that field. */
static struct htc_plan_params htc_test_default_params(void)
{
  struct htc_plan_params p;
  p.cap = 1000;
  p.high_pct = 85;
  p.low_pct = 75;
  p.quota_on = 1;
  p.share_pct = 10;
  p.draining = 0;
  return p;
}

static void test_plan_at_high_inactive(void **state)
{
  struct htc_acct *a = htc_acct_new();
  struct htc_plan_params p = htc_test_default_params();
  struct htc_plan plan;
  (void)state;

  htc_acct_add(a, HTC_OWNER_NONE, 850);
  htc_plan_eviction(a, &p, &plan);
  assert_int_equal(plan.active, 0);
  assert_int_equal((int)plan.nsteps, 0);
  assert_int_equal(plan.oldest, 0u);

  htc_acct_free(a);
}

static void test_plan_above_high(void **state)
{
  struct htc_acct *a = htc_acct_new();
  struct htc_plan_params p = htc_test_default_params();
  struct htc_plan plan;
  (void)state;

  htc_acct_add(a, HTC_OWNER_NONE, 851);
  htc_plan_eviction(a, &p, &plan);
  assert_int_equal(plan.active, 1);
  assert_int_equal(plan.target, 750u);
  assert_int_equal((int)plan.nsteps, 0);
  assert_int_equal(plan.oldest, 101u);

  htc_acct_free(a);
}

static void test_plan_draining(void **state)
{
  struct htc_acct *a = htc_acct_new();
  struct htc_plan_params p = htc_test_default_params();
  struct htc_plan plan;
  (void)state;

  p.draining = 1;

  htc_acct_add(a, HTC_OWNER_NONE, 800);
  htc_plan_eviction(a, &p, &plan);
  assert_int_equal(plan.active, 1);
  assert_int_equal(plan.oldest, 50u);

  htc_acct_add(a, HTC_OWNER_NONE, -50); /* total now 750 */
  htc_plan_eviction(a, &p, &plan);
  assert_int_equal(plan.active, 0);

  htc_acct_free(a);
}

static void test_plan_share_first(void **state)
{
  struct htc_acct *a = htc_acct_new();
  struct htc_plan_params p = htc_test_default_params();
  struct htc_plan plan;
  (void)state;

  htc_acct_add(a, "a:f", 300);
  htc_acct_add(a, "a:q", 50);
  htc_acct_add(a, HTC_OWNER_NONE, 501);

  htc_plan_eviction(a, &p, &plan);
  assert_int_equal(plan.active, 1);
  assert_int_equal(plan.share, 100u);
  assert_int_equal((int)plan.nsteps, 1);
  assert_string_equal(plan.steps[0].owner, "a:f");
  assert_int_equal(plan.steps[0].trim, 200u);
  assert_int_equal(plan.oldest, 0u);

  htc_acct_free(a);
}

static void test_plan_steps_then_none(void **state)
{
  struct htc_acct *a = htc_acct_new();
  struct htc_plan_params p = htc_test_default_params();
  struct htc_plan plan;
  (void)state;

  /* a:f sits exactly at the share -- not strictly over it. */
  htc_acct_add(a, "a:f", 100);
  htc_acct_add(a, "a:q", 90);
  htc_acct_add(a, HTC_OWNER_NONE, 670);

  htc_plan_eviction(a, &p, &plan);
  assert_int_equal(plan.active, 1);
  assert_int_equal((int)plan.nsteps, 0);
  assert_int_equal(plan.truncated, 0);
  assert_int_equal(plan.oldest, 110u);

  htc_acct_free(a);
}

static void test_plan_dash_exempt(void **state)
{
  struct htc_acct *a = htc_acct_new();
  struct htc_plan_params p = htc_test_default_params();
  struct htc_plan plan;
  (void)state;

  htc_acct_add(a, HTC_OWNER_NONE, 900);
  htc_plan_eviction(a, &p, &plan);
  assert_int_equal(plan.active, 1);
  assert_int_equal((int)plan.nsteps, 0);
  assert_int_equal(plan.oldest, 150u);

  htc_acct_free(a);
}

static void test_plan_largest_first(void **state)
{
  struct htc_acct *a = htc_acct_new();
  struct htc_plan_params p = htc_test_default_params();
  struct htc_plan plan;
  (void)state;

  htc_acct_add(a, "a:a", 300);
  htc_acct_add(a, "a:b", 500);
  htc_acct_add(a, "a:c", 200);

  htc_plan_eviction(a, &p, &plan);
  assert_int_equal(plan.active, 1);
  assert_int_equal((int)plan.nsteps, 3);
  assert_string_equal(plan.steps[0].owner, "a:b");
  assert_int_equal(plan.steps[0].trim, 400u);
  assert_string_equal(plan.steps[1].owner, "a:a");
  assert_int_equal(plan.steps[1].trim, 200u);
  assert_string_equal(plan.steps[2].owner, "a:c");
  assert_int_equal(plan.steps[2].trim, 100u);
  assert_int_equal(plan.oldest, 0u);

  htc_acct_free(a);
}

static void test_plan_ip_and_server(void **state)
{
  struct htc_acct *a = htc_acct_new();
  struct htc_plan_params p = htc_test_default_params();
  struct htc_plan plan;
  (void)state;

  htc_acct_add(a, "i:c0000201", 200);
  htc_acct_add(a, "s:leaf", 150);
  htc_acct_add(a, HTC_OWNER_NONE, 520);

  htc_plan_eviction(a, &p, &plan);
  assert_int_equal(plan.active, 1);
  assert_int_equal((int)plan.nsteps, 2);
  assert_string_equal(plan.steps[0].owner, "i:c0000201");
  assert_int_equal(plan.steps[0].trim, 100u);
  assert_string_equal(plan.steps[1].owner, "s:leaf");
  assert_int_equal(plan.steps[1].trim, 50u);

  htc_acct_free(a);
}

static void test_plan_quota_off(void **state)
{
  struct htc_acct *a = htc_acct_new();
  struct htc_plan_params p = htc_test_default_params();
  struct htc_plan plan;
  (void)state;

  p.quota_on = 0;

  htc_acct_add(a, "a:f", 300);
  htc_acct_add(a, HTC_OWNER_NONE, 560);

  htc_plan_eviction(a, &p, &plan);
  assert_int_equal(plan.active, 1);
  assert_int_equal((int)plan.nsteps, 0);
  assert_int_equal(plan.share, 0u);
  assert_int_equal(plan.oldest, 110u);

  htc_acct_free(a);
}

static void test_plan_bad_pct(void **state)
{
  struct htc_acct *a = htc_acct_new();
  struct htc_plan_params p = htc_test_default_params();
  struct htc_plan plan;
  (void)state;

  htc_acct_add(a, "a:f", 300);
  htc_acct_add(a, HTC_OWNER_NONE, 560);

  p.share_pct = 0;
  htc_plan_eviction(a, &p, &plan);
  assert_int_equal((int)plan.nsteps, 0);

  p.share_pct = 100;
  htc_plan_eviction(a, &p, &plan);
  assert_int_equal((int)plan.nsteps, 0);

  htc_acct_free(a);
}

static void test_plan_truncated_blocks_oldest(void **state)
{
  struct htc_acct *a = htc_acct_new();
  struct htc_plan_params p = htc_test_default_params();
  struct htc_plan plan;
  char owner[16];
  int i;
  (void)state;

  for (i = 0; i < 40; i++) {
    snprintf(owner, sizeof(owner), "a:o%02d", i);
    htc_acct_add(a, owner, 120);
  }

  htc_plan_eviction(a, &p, &plan);
  assert_int_equal(plan.active, 1);
  assert_int_equal((int)plan.nsteps, HTC_PLAN_MAX_STEPS);
  assert_int_equal(plan.truncated, 1);
  assert_int_equal(plan.oldest, 0u);

  htc_acct_free(a);
}

static void test_plan_zero_cap(void **state)
{
  struct htc_acct *a = htc_acct_new();
  struct htc_plan_params p = htc_test_default_params();
  struct htc_plan plan;
  (void)state;

  p.cap = 0;
  htc_acct_add(a, HTC_OWNER_NONE, 5000);

  htc_plan_eviction(a, &p, &plan);
  assert_int_equal(plan.active, 0);

  htc_acct_free(a);
}

static void test_plan_sanitize(void **state)
{
  struct htc_acct *a = htc_acct_new();
  struct htc_plan_params p = htc_test_default_params();
  struct htc_plan plan;
  (void)state;

  htc_acct_add(a, HTC_OWNER_NONE, 900);

  p.high_pct = 80;
  p.low_pct = 90;
  htc_plan_eviction(a, &p, &plan);
  assert_int_equal(plan.target, 700u);

  p.high_pct = 0;
  p.low_pct = 0;
  htc_plan_eviction(a, &p, &plan);
  assert_int_equal(plan.target, 750u);

  /* Fix round 1 (controller ruling, FINDING 1): the brief's unfloored
   * "low >= high -> low = high - 10" lets low go negative whenever an
   * oper sets HIGH_WATERMARK to 1..9 (feature_set's FEAT_INT path has
   * no min/max -- ircd_features.c:1601-1617), and target = cap*low/100
   * then wraps to ~2^64 under unsigned arithmetic instead of landing
   * at a sane value near 0. The ruling floors it: low = high>10 ?
   * high-10 : 0. */

  /* high 5, low 75: low>=high (75>=5), high is NOT >10, so low floors
   * at 0 instead of wrapping to -5 (~2^64 unsigned). This is exactly
   * the wrap FINDING 1 reported. */
  p.high_pct = 5;
  p.low_pct = 75;
  htc_plan_eviction(a, &p, &plan);
  assert_int_equal(plan.target, 0u);

  /* Same config, draining, total 900: with the floor in place the
   * plan stays active (900 > target 0) and reports the full total as
   * oldest (no owner is over share -- only the exempt '-' owner holds
   * anything) instead of the old code's silent total>cap*high/100
   * (900 > 1000*5/100=50) vs draining (900 > wrapped target) giving
   * two different "active" answers for the same state, or crashing on
   * total - target. */
  {
    struct htc_acct *a2 = htc_acct_new();
    struct htc_plan_params pd = p; /* high=5, low=75 (sanitizes to 0) */
    struct htc_plan plan2;

    pd.draining = 1;
    htc_acct_add(a2, HTC_OWNER_NONE, 900);
    htc_plan_eviction(a2, &pd, &plan2);
    assert_int_equal(plan2.active, 1);
    assert_int_equal((int)plan2.nsteps, 0);
    assert_int_equal(plan2.oldest, 900u);

    htc_acct_free(a2);
  }

  /* high 150 is out of the 1..100 range -> sanitizes to 85, proven via
   * the active decision: 851 is over cap*85/100 (850) but would NOT
   * be over cap*150/100 (1500) if the out-of-range value leaked
   * through unsanitized. */
  {
    struct htc_acct *a3 = htc_acct_new();
    struct htc_plan_params ph = htc_test_default_params();
    struct htc_plan plan3;

    ph.high_pct = 150;
    htc_acct_add(a3, HTC_OWNER_NONE, 851);
    htc_plan_eviction(a3, &ph, &plan3);
    assert_int_equal(plan3.active, 1);

    htc_acct_free(a3);
  }

  /* low -3 is out of range -- same reset-to-75 path as low 0 above --
   * then the ordinary low>=high rule applies on top (75 < 85, so low
   * stays at the reset default here). */
  p.high_pct = 85;
  p.low_pct = -3;
  htc_plan_eviction(a, &p, &plan);
  assert_int_equal(plan.target, 750u);

  /* high 100, low 100: both already in range, so low>=high (100>=100)
   * fires and low = high-10 = 90. */
  p.high_pct = 100;
  p.low_pct = 100;
  htc_plan_eviction(a, &p, &plan);
  assert_int_equal(plan.target, 900u);

  htc_acct_free(a);
}

static void test_owner_share_hook(void **state)
{
  struct htc_plan_params p = htc_test_default_params();
  (void)state;

  /* Documents the Amendment-A hook: today it ignores the owner and
   * always returns the plan's flat share (cap * share_pct / 100). */
  assert_int_equal(htc_owner_share(&p, "a:bob"), 100u);
  assert_int_equal(htc_owner_share(&p, "s:leaf"), 100u);
  assert_int_equal(htc_owner_share(&p, HTC_OWNER_NONE), 100u);
}

static void test_effective_days(void **state)
{
  const uint64_t now = 1700000000000ULL;
  (void)state;

  assert_int_equal(htc_effective_days(7, 0, now), 7);
  assert_int_equal(htc_effective_days(7, now - 216000000ULL, now), 2);
  assert_int_equal(htc_effective_days(7, now - 1800000ULL, now), 1);
  assert_int_equal(htc_effective_days(7, now - 777600000ULL, now), 7);
  assert_int_equal(htc_effective_days(0, now - 276480000ULL, now), 3);
  assert_int_equal(htc_effective_days(7, now + 5000ULL, now), 1);
  assert_int_equal(htc_effective_days(0, 0, now), 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_parse_ms),
    cmocka_unit_test(test_owner_account),
    cmocka_unit_test(test_owner_star),
    cmocka_unit_test(test_owner_ipv4),
    cmocka_unit_test(test_owner_ipv6_64),
    cmocka_unit_test(test_owner_unspec_ip),
    cmocka_unit_test(test_owner_none),
    cmocka_unit_test(test_owner_overflow),
    cmocka_unit_test(test_msg_key),
    cmocka_unit_test(test_msg_key_parse),
    cmocka_unit_test(test_bt_key_order),
    cmocka_unit_test(test_bt_key_roundtrip),
    cmocka_unit_test(test_bt_be64_bound),
    cmocka_unit_test(test_bo_key_split),
    cmocka_unit_test(test_bo_prefix_isolates),
    cmocka_unit_test(test_rec_roundtrip),
    cmocka_unit_test(test_rec_parse_rejects),
    cmocka_unit_test(test_size_pack),
    cmocka_unit_test(test_row_bytes),
    cmocka_unit_test(test_msgid_key),
    cmocka_unit_test(test_reply_child_key),
    cmocka_unit_test(test_reply_prefix),
    cmocka_unit_test(test_acct_add_sub),
    cmocka_unit_test(test_acct_clamps),
    cmocka_unit_test(test_acct_top),
    cmocka_unit_test(test_acct_many),
    cmocka_unit_test(test_plan_at_high_inactive),
    cmocka_unit_test(test_plan_above_high),
    cmocka_unit_test(test_plan_draining),
    cmocka_unit_test(test_plan_share_first),
    cmocka_unit_test(test_plan_steps_then_none),
    cmocka_unit_test(test_plan_dash_exempt),
    cmocka_unit_test(test_plan_largest_first),
    cmocka_unit_test(test_plan_ip_and_server),
    cmocka_unit_test(test_plan_quota_off),
    cmocka_unit_test(test_plan_bad_pct),
    cmocka_unit_test(test_plan_truncated_blocks_oldest),
    cmocka_unit_test(test_plan_zero_cap),
    cmocka_unit_test(test_plan_sanitize),
    cmocka_unit_test(test_owner_share_hook),
    cmocka_unit_test(test_effective_days),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
