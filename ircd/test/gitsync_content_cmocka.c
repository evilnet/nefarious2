/*
 * gitsync_content_cmocka.c - what a sync does with the content it pulled
 *
 * gitsync_content_hash() tells GitSync whether the content it pulled is
 * the content it applied last (then nothing is written or rehashed): it
 * must change when any byte does, wherever it is.
 *
 * gitsync_content_verdict() decides: content applied last is left alone;
 * content refused last (it did not parse, the backup was restored) is
 * left alone too, until it changes, unless the sync was forced (an
 * operator's GITSYNC force, or GitSync starting); anything else is
 * applied.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "gitsync_content.h"

static char *content_of(size_t len, char fill)
{
  char *c = malloc(len + 1);

  assert_non_null(c);
  memset(c, fill, len);
  c[len] = '\0';
  return c;
}

static int same_hash(const char *a, size_t alen, const char *b, size_t blen)
{
  char ha[GITSYNC_HASHLEN], hb[GITSYNC_HASHLEN];

  gitsync_content_hash(a, alen, ha, sizeof(ha));
  gitsync_content_hash(b, blen, hb, sizeof(hb));
  return 0 == strcmp(ha, hb);
}

/** The same content hashes the same. */
static void same_content_same_hash(void **state)
{
  char *a = content_of(5000, 'k'), *b = content_of(5000, 'k');

  (void)state;
  assert_true(same_hash(a, 5000, b, 5000));
  free(a);
  free(b);
}

/** A byte changed near the start. */
static void change_at_start(void **state)
{
  char *a = content_of(5000, 'k'), *b = content_of(5000, 'k');

  (void)state;
  b[10] = 'x';
  assert_false(same_hash(a, 5000, b, 5000));
  free(a);
  free(b);
}

/** A byte changed past the first kilobyte, the length the same (a
 * K-line's reason edited, an address changed): a different hash. */
static void change_past_first_kilobyte(void **state)
{
  char *a = content_of(5000, 'k'), *b = content_of(5000, 'k');

  (void)state;
  b[2000] = 'x';
  assert_false(same_hash(a, 5000, b, 5000));
  b[2000] = 'k';
  b[4999] = 'x';
  assert_false(same_hash(a, 5000, b, 5000));
  free(a);
  free(b);
}

/** Two bytes swapped: a different hash. */
static void bytes_swapped(void **state)
{
  char a[] = "Kill { host = \"*@10.0.0.1\"; reason = \"ab\"; };";
  char b[] = "Kill { host = \"*@10.0.0.1\"; reason = \"ba\"; };";

  (void)state;
  assert_false(same_hash(a, strlen(a), b, strlen(b)));
}

/** A different length. */
static void different_length(void **state)
{
  char *a = content_of(5000, 'k');

  (void)state;
  assert_false(same_hash(a, 5000, a, 4999));
  free(a);
}

/* ------------------------------------------------------------------ */
/* The verdict                                                          */
/* ------------------------------------------------------------------ */

/** Nothing applied or refused yet (a first sync): apply. */
static void first_content_is_applied(void **state)
{
  (void)state;
  assert_int_equal(GITSYNC_CONTENT_APPLY, gitsync_content_verdict("a", "", "", 0));
  assert_int_equal(GITSYNC_CONTENT_APPLY, gitsync_content_verdict("a", "", "", 1));
}

/** The content applied last: nothing, forced or not. */
static void applied_content_is_unchanged(void **state)
{
  (void)state;
  assert_int_equal(GITSYNC_CONTENT_UNCHANGED, gitsync_content_verdict("a", "a", "", 0));
  assert_int_equal(GITSYNC_CONTENT_UNCHANGED, gitsync_content_verdict("a", "a", "b", 1));
}

/** The content refused last: a periodic sync leaves it alone. */
static void refused_content_is_skipped(void **state)
{
  (void)state;
  assert_int_equal(GITSYNC_CONTENT_REFUSED, gitsync_content_verdict("b", "a", "b", 0));
  assert_int_equal(GITSYNC_CONTENT_REFUSED, gitsync_content_verdict("b", "", "b", 0));
}

/** A forced sync (GITSYNC force, GitSync starting) tries it again. */
static void forced_sync_retries_refused_content(void **state)
{
  (void)state;
  assert_int_equal(GITSYNC_CONTENT_APPLY, gitsync_content_verdict("b", "a", "b", 1));
}

/** Content that changed since it was refused is applied. */
static void changed_content_is_applied(void **state)
{
  (void)state;
  assert_int_equal(GITSYNC_CONTENT_APPLY, gitsync_content_verdict("c", "a", "b", 0));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(first_content_is_applied),
    cmocka_unit_test(applied_content_is_unchanged),
    cmocka_unit_test(refused_content_is_skipped),
    cmocka_unit_test(forced_sync_retries_refused_content),
    cmocka_unit_test(changed_content_is_applied),
    cmocka_unit_test(same_content_same_hash),
    cmocka_unit_test(change_at_start),
    cmocka_unit_test(change_past_first_kilobyte),
    cmocka_unit_test(bytes_swapped),
    cmocka_unit_test(different_length),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
