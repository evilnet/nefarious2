/* cmocka suite for the webhook signature check and the replay ring
 * (include/kc/kc_webhook_sig.h).  The vector is shared with the SPI's
 * WebhookSignatureTest, so both sides agree on the bytes that are signed. */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <cmocka.h>

#include "../../include/kc/kc_webhook_sig.h"

#define SECRET "x3-webhook-secret"
#define T      1790200000LL
#define BODY   "{\"id\":\"e1\",\"resourceType\":\"USER\",\"operationType\":\"DELETE\"," \
               "\"resourcePath\":\"users/0b4a2f0e-1d4c-4c4a-9a1e-000000000001\",\"realmName\":\"testnet\"}"
#define GOOD   "t=1790200000,v1=b8eb25dedf41b9e88b658f97537f5ec2cce9dcbd7c1915edbaf01e1b5e15e4f6"
#define OTHER  "t=1790200000,v1=c527185925ca061a29c6a9fa7c2a8488537f282486af4ccb550cca49a8dacf95"

static void test_good_signature_within_window(void **s)
{
  long long t = 0;
  (void)s;
  assert_int_equal(kc_webhook_sig_verify(SECRET, GOOD, BODY, strlen(BODY), T + 10, 300, &t), KC_SIG_OK);
  assert_true(t == T);
  assert_int_equal(kc_webhook_sig_verify(SECRET, GOOD, BODY, strlen(BODY), T - 299, 300, NULL), KC_SIG_OK);
}

static void test_stale_timestamp_is_refused(void **s)
{
  (void)s;   /* Review focus 1 */
  assert_int_equal(kc_webhook_sig_verify(SECRET, GOOD, BODY, strlen(BODY), T + 301, 300, NULL), KC_SIG_STALE);
  assert_int_equal(kc_webhook_sig_verify(SECRET, GOOD, BODY, strlen(BODY), T - 301, 300, NULL), KC_SIG_STALE);
}

static void test_wrong_secret_body_or_shape(void **s)
{
  (void)s;
  assert_int_equal(kc_webhook_sig_verify("another", GOOD, BODY, strlen(BODY), T, 300, NULL), KC_SIG_MISMATCH);
  assert_int_equal(kc_webhook_sig_verify(SECRET, OTHER, BODY, strlen(BODY), T, 300, NULL), KC_SIG_MISMATCH);
  assert_int_equal(kc_webhook_sig_verify(SECRET, GOOD, BODY "x", strlen(BODY) + 1, T, 300, NULL), KC_SIG_MISMATCH);
  assert_int_equal(kc_webhook_sig_verify(SECRET, NULL, BODY, strlen(BODY), T, 300, NULL), KC_SIG_MISSING);
  assert_int_equal(kc_webhook_sig_verify(SECRET, "", BODY, strlen(BODY), T, 300, NULL), KC_SIG_MISSING);
  assert_int_equal(kc_webhook_sig_verify(SECRET, "v1=b8eb", BODY, strlen(BODY), T, 300, NULL), KC_SIG_MALFORMED);
  assert_int_equal(kc_webhook_sig_verify(SECRET, "t=1790200000,v1=zz", BODY, strlen(BODY), T, 300, NULL), KC_SIG_MALFORMED);
  assert_int_equal(kc_webhook_sig_verify(SECRET, "t=abc,v1=b8eb25dedf41b9e88b658f97537f5ec2cce9dcbd7c1915edbaf01e1b5e15e4f6", BODY, strlen(BODY), T, 300, NULL), KC_SIG_MALFORMED);
  assert_string_equal(kc_sig_result_name(KC_SIG_STALE), "stale");
}

static void test_replay_is_refused(void **s)
{
  struct kc_replay_ring r;
  int i;
  char id[40];
  (void)s;   /* Review focus 2 */
  kc_replay_ring_init(&r);
  /* (id, signature time t, receipt time now, window) */
  assert_int_equal(kc_replay_ring_seen(&r, "e1", T, T, 300), 0);
  assert_int_equal(kc_replay_ring_seen(&r, "e1", T, T + 5, 300), 1);
  assert_int_equal(kc_replay_ring_seen(&r, "e2", T + 5, T + 5, 300), 0);
  assert_int_equal(kc_replay_ring_seen(&r, "e1", T + 400, T + 400, 300), 0);   /* re-signed after the window: not a replay */
  for (i = 0; i < KC_REPLAY_RING + 5; i++) {
    snprintf(id, sizeof(id), "x%d", i);
    kc_replay_ring_seen(&r, id, T, T, 300);
  }
  assert_int_equal(kc_replay_ring_seen(&r, "x0", T, T, 300), 0);         /* evicted, remembered again */
  assert_int_equal(kc_replay_ring_seen(&r, "x0", T, T, 300), 1);
  assert_int_equal(kc_replay_ring_seen(&r, NULL, T, T, 300), 0);
}

/* Review finding 3a: an id re-signed after its window is remembered afresh
 * in place, so a replay of THAT sighting is still refused. */
static void test_replay_after_resign_is_refused(void **s)
{
  struct kc_replay_ring r;
  (void)s;
  kc_replay_ring_init(&r);
  assert_int_equal(kc_replay_ring_seen(&r, "e1", T, T, 300), 0);
  assert_int_equal(kc_replay_ring_seen(&r, "e1", T + 400, T + 400, 300), 0);   /* the SPI signed it again */
  assert_int_equal(kc_replay_ring_seen(&r, "e1", T + 400, T + 405, 300), 1);   /* a copy of that one: replay */
}

/* Review finding 3b: the ring lives by the signature's own time, so an id
 * stays refusable for exactly as long as its signature stays fresh, whatever
 * the SPI's clock skew. */
static void test_replay_ring_keeps_signature_time(void **s)
{
  struct kc_replay_ring r;
  (void)s;
  kc_replay_ring_init(&r);
  assert_int_equal(kc_replay_ring_seen(&r, "e1", T + 200, T, 300), 0);          /* SPI clock 200 s ahead */
  assert_int_equal(kc_replay_ring_seen(&r, "e1", T + 200, T + 350, 300), 1);    /* signature still fresh: replay */
  assert_int_equal(kc_replay_ring_seen(&r, "e1", T + 200, T + 501, 300), 0);    /* signature stale now: no longer a replay (verify refuses it as stale) */
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_good_signature_within_window),
    cmocka_unit_test(test_stale_timestamp_is_refused),
    cmocka_unit_test(test_wrong_secret_body_or_shape),
    cmocka_unit_test(test_replay_is_refused),
    cmocka_unit_test(test_replay_after_resign_is_refused),
    cmocka_unit_test(test_replay_ring_keeps_signature_time),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
