/* webpush_keyring_cmocka.c - CMocka tests for the VAPID key ring
 * (webpush_keyring.c).  The module is pure: no ircd deps, no stubs.
 *
 * Pins the convergence rules from
 * .claude/para/projects/webpush-vapid-key-plan.md: union merge is
 * idempotent, current = highest generation / oldest created / id bytes,
 * a newcomer's boot key never displaces the network key, retired keys
 * prune only when unreferenced past a grace period (or past the expiry
 * window), and the store/wire record round-trips.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>

#include "../../include/webpush_keyring.h"

#define T0 1800000000LL
#define DAY 86400LL

static struct webpush_key mk(const char *id, unsigned int gen, long long created,
                             const char *origin, int manual)
{
  struct webpush_key k;
  size_t i;
  memset(&k, 0, sizeof(k));
  strncpy(k.id, id, sizeof(k.id) - 1);
  for (i = 0; i < sizeof(k.priv); i++)
    k.priv[i] = (unsigned char)(i + id[0]);
  k.generation = gen;
  k.created = created;
  strncpy(k.origin, origin, sizeof(k.origin) - 1);
  k.manual = manual;
  return k;
}

static void test_union_is_idempotent(void **state)
{
  struct webpush_keyring ring;
  struct webpush_key a = mk("AAA", 0, T0, "one.example", 0);
  struct webpush_key a2 = mk("AAA", 5, T0 + 99, "other.example", 1);
  (void)state;

  webpush_keyring_init(&ring);
  assert_int_equal(webpush_keyring_add(&ring, &a), 1);
  assert_int_equal(ring.count, 1);

  /* Same id again: not added, and the existing entry is untouched --
   * keys are immutable, so a peer can never rewrite ours. */
  assert_int_equal(webpush_keyring_add(&ring, &a2), 0);
  assert_int_equal(ring.count, 1);
  assert_int_equal(webpush_keyring_find(&ring, "AAA")->generation, 0);
  assert_string_equal(webpush_keyring_find(&ring, "AAA")->origin, "one.example");

  assert_null(webpush_keyring_find(&ring, "BBB"));
  assert_null(webpush_keyring_find(&ring, ""));
  assert_null(webpush_keyring_find(&ring, NULL));
}

static void test_add_rejects_invalid_and_full(void **state)
{
  struct webpush_keyring ring;
  struct webpush_key bad = mk("", 0, T0, "one", 0);
  char id[8];
  int i;
  (void)state;

  webpush_keyring_init(&ring);
  assert_int_equal(webpush_keyring_add(&ring, &bad), -1);
  assert_int_equal(webpush_keyring_add(&ring, NULL), -1);

  for (i = 0; i < WEBPUSH_KEYRING_MAX; i++) {
    struct webpush_key k;
    snprintf(id, sizeof(id), "K%02d", i);
    k = mk(id, 0, T0 + i, "one", 0);
    assert_int_equal(webpush_keyring_add(&ring, &k), 1);
  }
  {
    struct webpush_key k = mk("OVER", 0, T0, "one", 0);
    assert_int_equal(webpush_keyring_add(&ring, &k), -1);
  }
  assert_int_equal(ring.count, WEBPUSH_KEYRING_MAX);
}

static void test_current_rule(void **state)
{
  struct webpush_keyring ring;
  struct webpush_key older = mk("ZZZ", 0, T0 - DAY, "one", 0);
  struct webpush_key newer = mk("AAA", 0, T0, "two", 0);
  struct webpush_key rotated = mk("MMM", 1, T0 + DAY, "one", 0);
  (void)state;

  webpush_keyring_init(&ring);
  assert_null(webpush_keyring_current(&ring));

  /* Fresh network: two independently generated boot keys link.  The
   * OLDER one is current regardless of id bytes; the other is retired. */
  webpush_keyring_add(&ring, &newer);
  webpush_keyring_add(&ring, &older);
  assert_string_equal(webpush_keyring_current(&ring)->id, "ZZZ");

  /* A deliberate rotation (generation 1) wins even though it is the
   * youngest key. */
  webpush_keyring_add(&ring, &rotated);
  assert_string_equal(webpush_keyring_current(&ring)->id, "MMM");

  /* A newcomer's boot key (generation 0, young) never displaces it. */
  {
    struct webpush_key newcomer = mk("BBB", 0, T0 + 2 * DAY, "three", 0);
    webpush_keyring_add(&ring, &newcomer);
    assert_string_equal(webpush_keyring_current(&ring)->id, "MMM");
  }

  /* Both sides of a split rotated: same generation, the older wins. */
  {
    struct webpush_key other_side = mk("NNN", 1, T0 + DAY + 1, "two", 0);
    webpush_keyring_add(&ring, &other_side);
    assert_string_equal(webpush_keyring_current(&ring)->id, "MMM");
  }

  /* Exact tie on generation and created: id bytes decide, deterministically. */
  {
    struct webpush_key tie = mk("LLL", 1, T0 + DAY, "four", 0);
    webpush_keyring_add(&ring, &tie);
    assert_string_equal(webpush_keyring_current(&ring)->id, "LLL");
  }

  /* The manual flag plays no part in the rule: a manual key wins only by
   * the generation it was imported at. */
  {
    struct webpush_key manual_old = mk("CCC", 0, T0 - 10 * DAY, "one", 1);
    webpush_keyring_add(&ring, &manual_old);
    assert_string_equal(webpush_keyring_current(&ring)->id, "LLL");
  }
}

static void test_next_generation(void **state)
{
  struct webpush_keyring ring;
  struct webpush_key a = mk("AAA", 0, T0, "one", 0);
  struct webpush_key b = mk("BBB", 3, T0, "one", 0);
  (void)state;

  webpush_keyring_init(&ring);
  assert_int_equal(webpush_keyring_next_generation(&ring), 0);
  webpush_keyring_add(&ring, &a);
  assert_int_equal(webpush_keyring_next_generation(&ring), 1);
  webpush_keyring_add(&ring, &b);
  assert_int_equal(webpush_keyring_next_generation(&ring), 4);
}

static void test_prunable(void **state)
{
  struct webpush_keyring ring;
  struct webpush_key cur = mk("CUR", 1, T0, "one", 0);
  struct webpush_key unref = mk("UNREF", 0, T0 - DAY, "two", 0);
  struct webpush_key held = mk("HELD", 0, T0 - DAY, "two", 0);
  struct webpush_key ancient = mk("OLD", 0, T0 - 400 * DAY, "two", 0);
  struct webpush_key fresh = mk("FRESH", 0, T0 - 60, "three", 0);
  (void)state;

  webpush_keyring_init(&ring);
  webpush_keyring_add(&ring, &cur);
  webpush_keyring_add(&ring, &unref);
  webpush_keyring_add(&ring, &held);
  webpush_keyring_add(&ring, &ancient);
  webpush_keyring_add(&ring, &fresh);
  webpush_keyring_find(&ring, "HELD")->refs = 3;
  webpush_keyring_find(&ring, "OLD")->refs = 3;

  /* The current key is never prunable, referenced or not. */
  assert_int_equal(webpush_key_prunable(&ring, webpush_keyring_find(&ring, "CUR"),
                                        T0, 180 * DAY, DAY), 0);
  /* A retired key nothing references goes once the grace has passed
   * (the newcomer's boot key, a day after boot). */
  assert_int_equal(webpush_key_prunable(&ring, webpush_keyring_find(&ring, "UNREF"),
                                        T0, 180 * DAY, DAY), 1);
  /* ...but not inside the grace: a peer's registration bound to it may
   * still be on its way. */
  assert_int_equal(webpush_key_prunable(&ring, webpush_keyring_find(&ring, "FRESH"),
                                        T0, 180 * DAY, DAY), 0);
  /* grace <= 0 prunes an unreferenced key at once. */
  assert_int_equal(webpush_key_prunable(&ring, webpush_keyring_find(&ring, "FRESH"),
                                        T0, 180 * DAY, 0), 1);
  /* A retired key with local subscriptions stays while young. */
  assert_int_equal(webpush_key_prunable(&ring, webpush_keyring_find(&ring, "HELD"),
                                        T0, 180 * DAY, DAY), 0);
  /* ...but past the expiry window it goes even if referenced: those
   * records aged out on the same clock. */
  assert_int_equal(webpush_key_prunable(&ring, webpush_keyring_find(&ring, "OLD"),
                                        T0, 180 * DAY, DAY), 1);
  /* expire <= 0 disables the age rule. */
  assert_int_equal(webpush_key_prunable(&ring, webpush_keyring_find(&ring, "OLD"),
                                        T0, 0, DAY), 0);

  assert_int_equal(webpush_keyring_remove(&ring, "UNREF"), 1);
  assert_int_equal(webpush_keyring_remove(&ring, "UNREF"), 0);
  assert_int_equal(ring.count, 4);
  assert_null(webpush_keyring_find(&ring, "UNREF"));
  assert_string_equal(webpush_keyring_current(&ring)->id, "CUR");
}

static void test_format_parse_roundtrip(void **state)
{
  struct webpush_key k = mk("BB", 7, T0, "hub.afternet.org", 1);
  struct webpush_key back;
  char text[WEBPUSH_KEY_TEXT_LEN];
  char small[8];
  (void)state;

  assert_int_equal(webpush_key_format(&k, text, sizeof(text)), 0);
  assert_int_equal(strncmp(text, "7|1800000000|hub.afternet.org|1|", 32), 0);
  assert_int_equal(webpush_key_format(&k, small, sizeof(small)), -1);

  assert_int_equal(webpush_key_parse("BB", text, &back), 0);
  assert_string_equal(back.id, "BB");
  assert_int_equal(back.generation, 7);
  assert_true(back.created == T0);
  assert_string_equal(back.origin, "hub.afternet.org");
  assert_int_equal(back.manual, 1);
  assert_int_equal(back.refs, 0);
  assert_memory_equal(back.priv, k.priv, sizeof(k.priv));

  /* Malformed records are rejected, never half-loaded. */
  assert_int_equal(webpush_key_parse("BB", "7|1800000000|hub|1", &back), -1);
  assert_int_equal(webpush_key_parse("BB", "7|1800000000|hub|1|notbase64!!", &back), -1);
  assert_int_equal(webpush_key_parse("BB", "7|1800000000|hub|1|AAAA", &back), -1);
  assert_int_equal(webpush_key_parse("BB", "x|1800000000|hub|1|AAAA", &back), -1);
  assert_int_equal(webpush_key_parse("", text, &back), -1);
  assert_int_equal(webpush_key_parse("BB", NULL, &back), -1);
}

static void test_record_key_id(void **state)
{
  char out[WEBPUSH_KEY_ID_LEN + 1];
  char small[4];
  (void)state;

  assert_int_equal(webpush_record_key_id("https://e|p|a|1800000000|KEYID", out, sizeof(out)), 0);
  assert_string_equal(out, "KEYID");

  /* Pre-ring records: 4 fields (armed) or 3 (no armed) -> absent. */
  assert_int_equal(webpush_record_key_id("https://e|p|a|1800000000", out, sizeof(out)), 1);
  assert_int_equal(webpush_record_key_id("https://e|p|a", out, sizeof(out)), 1);
  assert_int_equal(webpush_record_key_id("https://e|p|a|1800000000|", out, sizeof(out)), 1);
  assert_int_equal(webpush_record_key_id(NULL, out, sizeof(out)), 1);

  assert_int_equal(webpush_record_key_id("e|p|a|1|LONGKEYID", small, sizeof(small)), -1);
}

static void test_b64url(void **state)
{
  unsigned char in[32], back[32];
  char enc[64];
  size_t n = 0, i;
  (void)state;

  for (i = 0; i < sizeof(in); i++)
    in[i] = (unsigned char)(0xf8 + i * 7);
  assert_int_equal(webpush_b64url_encode(in, sizeof(in), enc, sizeof(enc)), 43);
  assert_null(strchr(enc, '='));
  assert_null(strchr(enc, '+'));
  assert_null(strchr(enc, '/'));
  assert_int_equal(webpush_b64url_decode(enc, strlen(enc), back, sizeof(back), &n), 0);
  assert_int_equal(n, 32);
  assert_memory_equal(in, back, 32);

  /* Overflow and junk are refused. */
  assert_int_equal(webpush_b64url_decode(enc, strlen(enc), back, 16, &n), -1);
  assert_int_equal(webpush_b64url_decode("ab$c", 4, back, sizeof(back), &n), -1);
  assert_int_equal(webpush_b64url_encode(in, sizeof(in), enc, 10), -1);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_union_is_idempotent),
    cmocka_unit_test(test_add_rejects_invalid_and_full),
    cmocka_unit_test(test_current_rule),
    cmocka_unit_test(test_next_generation),
    cmocka_unit_test(test_prunable),
    cmocka_unit_test(test_format_parse_roundtrip),
    cmocka_unit_test(test_record_key_id),
    cmocka_unit_test(test_b64url),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
