/* cmocka suite for the before-connect merge rule (include/metadata_prereg.h):
 * what a client's METADATA writes made before registration do to the
 * account it logs in to during registration. */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>

#include "../../include/metadata_prereg.h"

#define VIS_PUBLIC  0
#define VIS_PRIVATE 1

static struct md_version live(uint64_t ms, const char *value, int vis)
{
  struct md_version v;

  memset(&v, 0, sizeof(v));
  v.st.ms = ms;
  v.st.node = 1;
  v.vis = vis;
  v.value = value;
  v.vlen = strlen(value);
  return v;
}

static struct md_version tomb(uint64_t ms)
{
  struct md_version v;

  memset(&v, 0, sizeof(v));
  v.st.ms = ms;
  v.st.node = 1;
  v.tombstone = 1;
  return v;
}

/* --- A tiny account: the rows a store holds, and the merge applied to it
 * the way metadata.c applies it (decide each write in order, write the
 * APPLY ones).  Lets the suite state the rule over a whole account. */
#define ACCT_MAX 16
struct acct_row { const char *key; struct md_version v; int used; };
struct acct { struct acct_row rows[ACCT_MAX]; };
struct pre { const char *key; struct md_version w; };

static struct acct_row *acct_find(struct acct *a, const char *key)
{
  int i;

  for (i = 0; i < ACCT_MAX; i++)
    if (a->rows[i].used && !strcmp(a->rows[i].key, key))
      return &a->rows[i];
  return NULL;
}

static void acct_put(struct acct *a, const char *key, struct md_version v)
{
  struct acct_row *r = acct_find(a, key);
  int i;

  if (!r)
    for (i = 0; i < ACCT_MAX && !r; i++)
      if (!a->rows[i].used)
        r = &a->rows[i];
  assert_non_null(r);
  r->key = key;
  r->v = v;
  r->used = 1;
}

static int acct_live_keys(const struct acct *a)
{
  int i, n = 0;

  for (i = 0; i < ACCT_MAX; i++)
    if (a->rows[i].used && !a->rows[i].v.tombstone)
      n++;
  return n;
}

/* Merge @a pre (n writes, in client order) into @a a; verdicts out. */
static void merge(struct acct *a, const struct pre *pre, int n, int logged_in,
                  int aware, int max_keys, enum md_prereg_verdict *out)
{
  int i, user_keys = acct_live_keys(a);

  if (!md_prereg_should_merge(logged_in, aware))
    return;
  for (i = 0; i < n; i++) {
    struct acct_row *r = acct_find(a, pre[i].key);

    out[i] = md_prereg_decide(r ? &r->v : NULL, &pre[i].w, &user_keys,
                              max_keys, 300);
    if (out[i] == MD_PREREG_APPLY)
      acct_put(a, pre[i].key, pre[i].w);
  }
  assert_int_equal(user_keys, acct_live_keys(a));
}

static const char *acct_value(struct acct *a, const char *key)
{
  struct acct_row *r = acct_find(a, key);

  return (r && !r->v.tombstone) ? r->v.value : NULL;
}

/* ------------------------------------------------------------------ */

static void test_should_merge(void **state)
{
  (void)state;
  assert_true(md_prereg_should_merge(1, 1));
  assert_false(md_prereg_should_merge(0, 1));   /* no login: its own keys */
  assert_false(md_prereg_should_merge(1, 0));   /* never metadata-aware */
  assert_false(md_prereg_should_merge(0, 0));
}

/* The before-connect value wins for its key; every other key is the
 * account's, untouched. */
static void test_prereg_wins_per_key_untouched_from_account(void **state)
{
  struct acct a;
  struct pre pre[2];
  enum md_prereg_verdict v[2];

  (void)state;
  memset(&a, 0, sizeof(a));
  acct_put(&a, "display-name", live(100, "stored", VIS_PUBLIC));
  acct_put(&a, "pronouns", live(100, "they", VIS_PUBLIC));
  acct_put(&a, "url", live(100, "http://x", VIS_PRIVATE));

  pre[0].key = "display-name"; pre[0].w = live(200, "mine", VIS_PUBLIC);
  pre[1].key = "status";       pre[1].w = live(201, "here", VIS_PUBLIC);
  merge(&a, pre, 2, 1, 1, 20, v);

  assert_int_equal(v[0], MD_PREREG_APPLY);
  assert_int_equal(v[1], MD_PREREG_APPLY);
  assert_string_equal(acct_value(&a, "display-name"), "mine");
  assert_string_equal(acct_value(&a, "status"), "here");
  assert_string_equal(acct_value(&a, "pronouns"), "they");
  assert_string_equal(acct_value(&a, "url"), "http://x");
  assert_int_equal(acct_find(&a, "url")->v.vis, VIS_PRIVATE);
  assert_int_equal(acct_live_keys(&a), 4);
}

/* An identical value (and visibility) changes nothing and announces
 * nothing, however new its stamp; the same value at another visibility is
 * a change. */
static void test_identical_value_is_a_noop(void **state)
{
  struct md_version stored = live(100, "same", VIS_PUBLIC);
  struct md_version w = live(500, "same", VIS_PUBLIC);
  struct md_version wp = live(500, "same", VIS_PRIVATE);
  int keys = 3;

  (void)state;
  assert_int_equal(md_prereg_decide(&stored, &w, &keys, 20, 300), MD_PREREG_SAME);
  assert_int_equal(keys, 3);
  assert_int_equal(md_prereg_decide(&stored, &wp, &keys, 20, 300), MD_PREREG_APPLY);
  assert_int_equal(keys, 3);
  /* identical even when the account's row is the newer one */
  stored.st.ms = 900;
  assert_int_equal(md_prereg_decide(&stored, &w, &keys, 20, 300), MD_PREREG_SAME);
}

/* A delete: of a stored key, applied (one key fewer); of a key the
 * account does not hold or already deleted, nothing. */
static void test_delete(void **state)
{
  struct md_version stored = live(100, "x", VIS_PUBLIC);
  struct md_version gone = tomb(100);
  struct md_version del = tomb(200);
  int keys = 2;

  (void)state;
  assert_int_equal(md_prereg_decide(&stored, &del, &keys, 20, 300), MD_PREREG_APPLY);
  assert_int_equal(keys, 1);
  assert_int_equal(md_prereg_decide(NULL, &del, &keys, 20, 300), MD_PREREG_ABSENT);
  assert_int_equal(md_prereg_decide(&gone, &del, &keys, 20, 300), MD_PREREG_ABSENT);
  assert_int_equal(keys, 1);
}

/* The account's row written after the client's SET (a newer stamp) stands,
 * for a set and for a delete; a row never stamped (0.0.0) is older than
 * anything. */
static void test_newer_account_row_stands(void **state)
{
  struct md_version stored = live(300, "later", VIS_PUBLIC);
  struct md_version later_delete = tomb(300);
  struct md_version legacy = live(0, "old", VIS_PUBLIC);
  struct md_version w = live(200, "mine", VIS_PUBLIC);
  struct md_version del = tomb(200);
  int keys = 1;

  (void)state;
  legacy.st.node = 0;
  assert_int_equal(md_prereg_decide(&stored, &w, &keys, 20, 300), MD_PREREG_SUPERSEDED);
  assert_int_equal(md_prereg_decide(&stored, &del, &keys, 20, 300), MD_PREREG_SUPERSEDED);
  assert_int_equal(md_prereg_decide(&later_delete, &w, &keys, 20, 300), MD_PREREG_SUPERSEDED);
  assert_int_equal(keys, 1);
  assert_int_equal(md_prereg_decide(&legacy, &w, &keys, 20, 300), MD_PREREG_APPLY);
  assert_int_equal(keys, 1);
}

/* Over the key cap at the merge: a new key is refused (and reported by
 * the caller), an update of a key the account holds fits, and a delete
 * the client sent earlier frees a place for a later new key. */
static void test_over_cap(void **state)
{
  struct acct a;
  struct pre pre[4];
  enum md_prereg_verdict v[4];

  (void)state;
  memset(&a, 0, sizeof(a));
  acct_put(&a, "k1", live(100, "a", VIS_PUBLIC));
  acct_put(&a, "k2", live(100, "b", VIS_PUBLIC));
  acct_put(&a, "k3", live(100, "c", VIS_PUBLIC));
  acct_put(&a, "k4", live(100, "d", VIS_PUBLIC));

  pre[0].key = "k5"; pre[0].w = live(200, "new", VIS_PUBLIC);
  pre[1].key = "k1"; pre[1].w = live(201, "changed", VIS_PUBLIC);
  pre[2].key = "k2"; pre[2].w = tomb(202);
  pre[3].key = "k6"; pre[3].w = live(203, "fits", VIS_PUBLIC);
  merge(&a, pre, 4, 1, 1, 4, v);

  assert_int_equal(v[0], MD_PREREG_LIMIT_KEYS);
  assert_int_equal(v[1], MD_PREREG_APPLY);
  assert_int_equal(v[2], MD_PREREG_APPLY);
  assert_int_equal(v[3], MD_PREREG_APPLY);
  assert_null(acct_value(&a, "k5"));
  assert_string_equal(acct_value(&a, "k1"), "changed");
  assert_null(acct_value(&a, "k2"));
  assert_string_equal(acct_value(&a, "k6"), "fits");
  assert_int_equal(acct_live_keys(&a), 4);
}

/* A negative METADATA_MAX_KEYS is 0, as metadata_check_limits() reads it. */
static void test_negative_cap_is_zero(void **state)
{
  struct md_version w = live(200, "v", VIS_PUBLIC);
  int keys = 0;

  (void)state;
  assert_int_equal(md_prereg_decide(NULL, &w, &keys, -1, 300), MD_PREREG_LIMIT_KEYS);
  assert_int_equal(keys, 0);
}

/* A value over the value limit at the merge (lowered since the SET). */
static void test_value_limit(void **state)
{
  struct md_version w = live(200, "0123456789", VIS_PUBLIC);
  struct md_version stored = live(100, "short", VIS_PUBLIC);
  int keys = 1;

  (void)state;
  assert_int_equal(md_prereg_decide(&stored, &w, &keys, 20, 9), MD_PREREG_LIMIT_VALUE);
  assert_int_equal(md_prereg_decide(&stored, &w, &keys, 20, 10), MD_PREREG_APPLY);
  assert_int_equal(keys, 1);
}

/* No login, or not metadata-aware when registration ends: the account is
 * not touched at all. */
static void test_no_merge_without_login_or_awareness(void **state)
{
  struct acct a;
  struct pre pre[1];
  enum md_prereg_verdict v[1] = { MD_PREREG_SAME };

  (void)state;
  memset(&a, 0, sizeof(a));
  acct_put(&a, "display-name", live(100, "stored", VIS_PUBLIC));
  pre[0].key = "display-name"; pre[0].w = live(200, "mine", VIS_PUBLIC);

  merge(&a, pre, 1, 0, 1, 20, v);       /* no login */
  assert_string_equal(acct_value(&a, "display-name"), "stored");
  merge(&a, pre, 1, 1, 0, 20, v);       /* not metadata-aware */
  assert_string_equal(acct_value(&a, "display-name"), "stored");
  assert_int_equal(v[0], MD_PREREG_SAME);   /* never decided */
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_should_merge),
    cmocka_unit_test(test_prereg_wins_per_key_untouched_from_account),
    cmocka_unit_test(test_identical_value_is_a_noop),
    cmocka_unit_test(test_delete),
    cmocka_unit_test(test_newer_account_row_stands),
    cmocka_unit_test(test_over_cap),
    cmocka_unit_test(test_negative_cap_is_zero),
    cmocka_unit_test(test_value_limit),
    cmocka_unit_test(test_no_merge_without_login_or_awareness),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
