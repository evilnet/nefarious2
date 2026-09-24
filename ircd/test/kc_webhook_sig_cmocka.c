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

/* Review focus 2, refined by the user's decision of 2026-09-24: a copy of an
 * accepted event signed no later than the last accepted copy is a replay; a
 * copy the SPI signed again later (its retry after a lost answer) is a
 * duplicate, answered 200 and never acted on twice. */
static void test_replay_is_refused(void **s)
{
  struct kc_replay_ring r;
  int i;
  char id[40];
  (void)s;
  kc_replay_ring_init(&r);
  assert_int_equal(kc_replay_ring_check(&r, "e1", T), KC_RING_NEW);
  assert_int_equal(kc_replay_ring_check(&r, "e1", T), KC_RING_REPLAY);       /* the same signed request again */
  assert_int_equal(kc_replay_ring_check(&r, "e2", T + 5), KC_RING_NEW);
  for (i = 0; i < KC_REPLAY_RING + 5; i++) {
    snprintf(id, sizeof(id), "x%d", i);
    kc_replay_ring_check(&r, id, T);
  }
  assert_int_equal(kc_replay_ring_check(&r, "x0", T), KC_RING_NEW);          /* evicted, remembered again */
  assert_int_equal(kc_replay_ring_check(&r, "x0", T), KC_RING_REPLAY);
  assert_int_equal(kc_replay_ring_check(&r, NULL, T), KC_RING_NEW);
  assert_int_equal(kc_replay_ring_check(&r, "", T), KC_RING_NEW);
}

static void test_retry_with_a_newer_signature_is_a_duplicate(void **s)
{
  struct kc_replay_ring r;
  (void)s;
  kc_replay_ring_init(&r);
  assert_int_equal(kc_replay_ring_check(&r, "e1", T), KC_RING_NEW);
  assert_int_equal(kc_replay_ring_check(&r, "e1", T + 2), KC_RING_DUPLICATE);   /* the SPI signed it again: its retry */
  assert_int_equal(kc_replay_ring_check(&r, "e1", T + 2), KC_RING_REPLAY);      /* a copy of that retry */
  assert_int_equal(kc_replay_ring_check(&r, "e1", T), KC_RING_REPLAY);          /* a copy of the original: older than the newest */
  assert_int_equal(kc_replay_ring_check(&r, "e1", T + 400), KC_RING_DUPLICATE); /* a late retry is still the sender's own */
}

/* An event the ircd could not queue (503) was not accepted: forgotten, so the
 * SPI's retry is new, not a duplicate that would be dropped. */
static void test_forget_makes_the_retry_new(void **s)
{
  struct kc_replay_ring r;
  (void)s;
  kc_replay_ring_init(&r);
  assert_int_equal(kc_replay_ring_check(&r, "e1", T), KC_RING_NEW);
  kc_replay_ring_forget(&r, "e1");
  assert_int_equal(kc_replay_ring_check(&r, "e1", T + 2), KC_RING_NEW);
  assert_int_equal(kc_replay_ring_check(&r, "e1", T + 2), KC_RING_REPLAY);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_good_signature_within_window),
    cmocka_unit_test(test_stale_timestamp_is_refused),
    cmocka_unit_test(test_wrong_secret_body_or_shape),
    cmocka_unit_test(test_replay_is_refused),
    cmocka_unit_test(test_retry_with_a_newer_signature_is_a_duplicate),
    cmocka_unit_test(test_forget_makes_the_retry_new),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
