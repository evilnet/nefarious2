/*
 * ml_fallback_cmocka.c - CMocka tests for the multiline fallback rule
 * (ml_fallback.c): which lines the preview shows and the N of
 * "[N more lines]".  Blank lines are neither shown nor counted; each
 * stored line with text is a unit (a concat part included, today).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "list.h"
#include "ml_fallback.h"

#define MAXL 16

struct batch {
  struct SLink link[MAXL];
  char rec[MAXL][32];
  int n;
};

/** Build a batch from "text" items; a leading '+' marks a concat part,
 * "" is a blank line. */
static void
mk(struct batch *b, const char *const *lines, int n)
{
  int i;
  memset(b, 0, sizeof(*b));
  for (i = 0; i < n; i++) {
    const char *t = lines[i];
    b->rec[i][0] = (t[0] == '+') ? 1 : 0;
    strcpy(b->rec[i] + 1, t[0] == '+' ? t + 1 : t);
    b->link[i].value.cp = b->rec[i];
    b->link[i].next = (i + 1 < n) ? &b->link[i + 1] : NULL;
  }
  b->n = n;
}

/** The texts the walk sends, joined with '|'. */
static void
walk(const struct batch *b, int shown, char *out, size_t outlen)
{
  const struct SLink *lp;
  int u = 0;
  out[0] = '\0';
  for (lp = ml_fallback_next(b->n ? &b->link[0] : NULL, &u, shown); lp;
       lp = ml_fallback_next(lp->next, &u, shown)) {
    if (out[0])
      strncat(out, "|", outlen - strlen(out) - 1);
    strncat(out, lp->value.cp + 1, outlen - strlen(out) - 1);
  }
}

static void
check(const char *const *lines, int n, int max, int want_shown, int want_left,
      const char *want_sent)
{
  struct batch b;
  char sent[256];
  int shown = -1, left = -1;

  mk(&b, lines, n);
  ml_fallback_plan(n ? &b.link[0] : NULL, max, &shown, &left);
  assert_int_equal(shown, want_shown);
  assert_int_equal(left, want_left);
  walk(&b, shown, sent, sizeof(sent));
  assert_string_equal(sent, want_sent);
}

static void
test_fits(void **state)
{
  static const char *const l[] = { "a", "b", "c" };
  (void)state;
  check(l, 3, 5, 3, 0, "a|b|c");
}

static void
test_truncated(void **state)
{
  static const char *const l[] = { "1", "2", "3", "4", "5", "6", "7", "8" };
  (void)state;
  check(l, 8, 5, 5, 3, "1|2|3|4|5");
}

/* The reviewer's example: 8 lines, 2 blanks among the first 5.  Every
 * sender now shows 5 lines and "[1 more lines]" (a legacy user saw that;
 * a client without the cap saw 3 lines and "[3 more lines]"). */
static void
test_blanks_in_preview(void **state)
{
  static const char *const l[] = { "1", "", "2", "", "3", "4", "5", "6" };
  (void)state;
  check(l, 8, 5, 5, 1, "1|2|3|4|5");
}

/* Blank lines after the preview are not "more lines" either. */
static void
test_blanks_left_over(void **state)
{
  static const char *const l[] = { "first", "", "", "", "", "", "last" };
  (void)state;
  check(l, 7, 5, 2, 0, "first|last");
}

static void
test_blank_first_line(void **state)
{
  static const char *const l[] = { "", "x2", "x3", "x4", "x5", "x6" };
  (void)state;
  check(l, 6, 5, 5, 0, "x2|x3|x4|x5|x6");
}

/* Today a concat part is a unit of its own. */
static void
test_concat_parts_count(void **state)
{
  static const char *const l[] = { "a", "+a2", "b", "+b2", "c", "d", "e" };
  (void)state;
  check(l, 7, 5, 5, 2, "a|a2|b|b2|c");
}

static void
test_zero_budget_and_empty(void **state)
{
  static const char *const l[] = { "a", "b" };
  (void)state;
  check(l, 2, 0, 0, 2, "");
  check(NULL, 0, 5, 0, 0, "");
}

static void
test_shows(void **state)
{
  char blank[2] = { 0, 0 };
  char text[3] = { 0, 'x', 0 };
  char part[3] = { 1, 'x', 0 };
  (void)state;
  assert_false(ml_fallback_shows(blank));
  assert_false(ml_fallback_shows(NULL));
  assert_true(ml_fallback_shows(text));
  assert_true(ml_fallback_shows(part));
}

int
main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_fits),
    cmocka_unit_test(test_truncated),
    cmocka_unit_test(test_blanks_in_preview),
    cmocka_unit_test(test_blanks_left_over),
    cmocka_unit_test(test_blank_first_line),
    cmocka_unit_test(test_concat_parts_count),
    cmocka_unit_test(test_zero_budget_and_empty),
    cmocka_unit_test(test_shows),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
