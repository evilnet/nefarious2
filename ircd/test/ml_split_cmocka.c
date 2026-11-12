/*
 * ml_split_cmocka.c - splitting a multiline batch's long lines
 *
 * ml_split_lines() (ircd/ml_split.c) splits every line of a client's
 * multiline batch whose relayed form would pass 510 bytes into
 * draft/multiline-concat parts of at most `room` bytes, so the joined
 * message stays byte-identical; m_batch.c holds the result to
 * MULTILINE_MAX_LINES.  A line is "<flag><text>", flag 1 = concat.
 *
 * Links the real ml_split.o, ircd_string.o and ircd_alloc.o; make_link()
 * is a calloc here.
 */
#include "config.h"

#include "ircd_alloc.h"
#include "list.h"
#include "ml_split.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

struct SLink *make_link(void)
{
  return (struct SLink *)calloc(1, sizeof(struct SLink));
}

/* Build a list from (concat, text) pairs. */
static struct SLink *batch(int n, const int *concat, const char **text)
{
  struct SLink *head = NULL, **tail = &head;
  int i;

  for (i = 0; i < n; i++) {
    struct SLink *lp = make_link();
    size_t len = strlen(text[i]);

    lp->value.cp = (char *)MyMalloc(len + 2);
    lp->value.cp[0] = (char)concat[i];
    memcpy(lp->value.cp + 1, text[i], len + 1);
    *tail = lp;
    tail = &lp->next;
  }
  return head;
}

static void drop(struct SLink *lp)
{
  while (lp) {
    struct SLink *next = lp->next;
    MyFree(lp->value.cp);
    free(lp);
    lp = next;
  }
}

/* Join as a multiline client does: concat lines with nothing between,
 * the others with a line feed. */
static char *joined(struct SLink *lp)
{
  static char out[8192];
  size_t pos = 0;
  int first = 1;

  for (; lp; lp = lp->next) {
    const char *t = lp->value.cp + 1;
    if (!first && !lp->value.cp[0])
      out[pos++] = '\n';
    memcpy(out + pos, t, strlen(t));
    pos += strlen(t);
    first = 0;
  }
  out[pos] = '\0';
  return out;
}

static char *rep(char c, size_t n)
{
  char *s = (char *)malloc(n + 1);
  memset(s, c, n);
  s[n] = '\0';
  return s;
}

static void test_at_budget_and_one_over(void **state)
{
  char *a = rep('a', 100), *b = rep('b', 101);
  const char *text[] = { a, b };
  int concat[] = { 0, 0 };
  struct SLink *l = batch(2, concat, text);
  (void)state;

  assert_int_equal(3, ml_split_lines(l, 100));   /* 100 stays, 101 -> 100 + 1 */
  assert_int_equal(100, strlen(l->value.cp + 1));
  assert_int_equal(0, l->next->value.cp[0]);     /* b's first part keeps its flag */
  assert_int_equal(100, strlen(l->next->value.cp + 1));
  assert_int_equal(1, l->next->next->value.cp[0]);  /* the rest is concat */
  assert_string_equal("b", l->next->next->value.cp + 1);
  {
    char want[300];
    snprintf(want, sizeof(want), "%s\n%s", a, b);
    assert_string_equal(want, joined(l));
  }
  drop(l); free(a); free(b);
}

static void test_three_or_more_parts(void **state)
{
  char *a = rep('x', 1000);
  const char *text[] = { a };
  int concat[] = { 0 };
  struct SLink *l = batch(1, concat, text), *lp;
  int n = 0;
  (void)state;

  assert_int_equal(5, ml_split_lines(l, 230));    /* 230*4 + 80 */
  for (lp = l; lp; lp = lp->next, n++) {
    assert_true(strlen(lp->value.cp + 1) <= 230);
    assert_int_equal(n ? 1 : 0, lp->value.cp[0]);
  }
  assert_int_equal(5, n);
  assert_string_equal(a, joined(l));
  drop(l); free(a);
}

static void test_already_concat_line(void **state)
{
  /* A client's own concat line keeps flag 1 on its first part; the join
   * across the client's line and our parts is seamless. */
  char *a = rep('a', 50), *b = rep('b', 150);
  const char *text[] = { a, b };
  int concat[] = { 0, 1 };
  struct SLink *l = batch(2, concat, text);
  char want[300];
  (void)state;

  assert_int_equal(3, ml_split_lines(l, 100));
  assert_int_equal(1, l->next->value.cp[0]);
  assert_int_equal(1, l->next->next->value.cp[0]);
  snprintf(want, sizeof(want), "%s%s", a, b);
  assert_string_equal(want, joined(l));
  drop(l); free(a); free(b);
}

static void test_empty_and_no_room(void **state)
{
  const char *text[] = { "", "short" };
  int concat[] = { 0, 0 };
  struct SLink *l = batch(2, concat, text);
  char *a = rep('a', 600);
  const char *t2[] = { a };
  struct SLink *l2 = batch(1, concat, t2);
  (void)state;

  assert_int_equal(2, ml_split_lines(l, 5));      /* a blank line never splits; "short" fits */
  assert_string_equal("", l->value.cp + 1);
  assert_int_equal(1, ml_split_lines(l2, 0));     /* room 0: nothing is split */
  assert_int_equal(600, strlen(l2->value.cp + 1));
  drop(l); drop(l2); free(a);
}

static void test_utf8_boundary(void **state)
{
  char text0[3 * 200 + 1];
  const char *text[] = { text0 };
  int concat[] = { 0 };
  struct SLink *l, *lp;
  int i;
  (void)state;

  for (i = 0; i < 200; i++)
    memcpy(text0 + 3 * i, "\342\202\254", 3);
  text0[600] = '\0';
  l = batch(1, concat, text);
  assert_int_equal(3, ml_split_lines(l, 250));    /* 249 + 249 + 102 */
  for (lp = l; lp; lp = lp->next) {
    const unsigned char *t = (const unsigned char *)lp->value.cp + 1;
    assert_int_equal(0, strlen((const char *)t) % 3);   /* whole characters */
    assert_int_equal(0xE2, t[0]);
  }
  assert_string_equal(text0, joined(l));
  drop(l);
}

static void test_colour_code_kept_whole(void **state)
{
  char t[220];
  const char *text[] = { t };
  int concat[] = { 0 };
  struct SLink *l;
  (void)state;

  memset(t, 'x', sizeof(t) - 1);
  t[sizeof(t) - 1] = '\0';
  memcpy(t + 98, "\00304,12", 6);       /* a code across the cut at 100 */
  l = batch(1, concat, text);
  assert_int_equal(3, ml_split_lines(l, 100));
  assert_int_equal(98, strlen(l->value.cp + 1));
  assert_memory_equal("\00304,12", l->next->value.cp + 1, 6);
  assert_string_equal(t, joined(l));
  drop(l);
}

/* ml_lines_check(): the per-line send checks of a multiline batch. */

/* A check that refuses a line holding 'X', upper-cases a line holding
 * '!' (a transform: a copy, like StripColor's), and counts its calls. */
static int calls;
static char upper[64];
static const char *check_x(const char *text, void *ctx)
{
  size_t i;
  (void)ctx;
  calls++;
  if (strchr(text, 'X'))
    return NULL;
  if (strchr(text, '!')) {
    for (i = 0; text[i] && i < sizeof(upper) - 1; i++)
      upper[i] = (text[i] >= 'a' && text[i] <= 'z') ? text[i] - 32 : text[i];
    upper[i] = '\0';
    return upper;
  }
  return text;
}

static void test_check_blank_lines_not_checked(void **state)
{
  const char *text[] = { "a", "", "b", "" };
  int concat[] = { 0, 0, 0, 0 };
  struct SLink *l = batch(4, concat, text);
  (void)state;

  calls = 0;
  assert_int_equal(0, ml_lines_check(l, check_x, NULL));
  assert_int_equal(2, calls);            /* only the lines with text */
  assert_string_equal("a\n\nb\n", joined(l));
  drop(l);
}

static void test_check_transform_keeps_flag(void **state)
{
  const char *text[] = { "one", "two!", "three!" };
  int concat[] = { 0, 1, 0 };
  struct SLink *l = batch(3, concat, text);
  (void)state;

  calls = 0;
  assert_int_equal(0, ml_lines_check(l, check_x, NULL));
  assert_string_equal("TWO!", l->next->value.cp + 1);
  assert_int_equal(1, l->next->value.cp[0]);          /* concat kept */
  assert_string_equal("THREE!", l->next->next->value.cp + 1);
  assert_int_equal(0, l->next->next->value.cp[0]);
  drop(l);
}

static void test_check_first_refusal_stops(void **state)
{
  const char *text[] = { "ok!", "bad X", "later!" };
  int concat[] = { 0, 0, 0 };
  struct SLink *l = batch(3, concat, text);
  (void)state;

  calls = 0;
  assert_int_equal(-1, ml_lines_check(l, check_x, NULL));
  assert_int_equal(2, calls);                         /* stopped at "bad X" */
  assert_string_equal("later!", l->next->next->value.cp + 1);  /* untouched */
  drop(l);
}

static void test_lines_bytes(void **state)
{
  /* "ab" + LF + "cd" (concat: no LF) + "e" + LF + "" = 2+1+2+2+1+1+0 */
  const char *text[] = { "ab", "cde", "f", "" };
  int concat[] = { 0, 1, 0, 0 };
  struct SLink *l = batch(4, concat, text);
  (void)state;

  assert_int_equal(2 + 3 + 1 + 1 + 1 + 0, ml_lines_bytes(l));
  ml_line_set_text(l->next, "c");                     /* a shorter line */
  assert_int_equal(2 + 1 + 1 + 1 + 1, ml_lines_bytes(l));
  assert_int_equal(1, l->next->value.cp[0]);
  assert_int_equal(0, ml_lines_bytes(NULL));
  drop(l);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_at_budget_and_one_over),
    cmocka_unit_test(test_three_or_more_parts),
    cmocka_unit_test(test_already_concat_line),
    cmocka_unit_test(test_empty_and_no_room),
    cmocka_unit_test(test_utf8_boundary),
    cmocka_unit_test(test_colour_code_kept_whole),
    cmocka_unit_test(test_check_blank_lines_not_checked),
    cmocka_unit_test(test_check_transform_keeps_flag),
    cmocka_unit_test(test_check_first_refusal_stops),
    cmocka_unit_test(test_lines_bytes),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
