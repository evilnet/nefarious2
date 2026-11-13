/*
 * dbuf_find_line_cmocka.c - dbuf_find_line(): the first complete line of a
 * receive queue that a matcher accepts, found without removing anything.
 *
 * The orphan hold (s_bsd.c input_held()) scans a held connection's queue
 * for a QUIT this way.  This drives the REAL dbuf.c (included), with the
 * buffer pool, the allocator and the flusher stubbed: lines across buffer
 * boundaries, CR LF and bare LF ends, a last line with no end yet, a line
 * longer than the scratch buffer, and that the queue is left as it was.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "../dbuf.c"

int feature_int(enum Feature feat) { return 10 * 1024 * 1024; }  /* BUFFERPOOL */
int feature_bool(enum Feature feat) { return 0; }
void flush_connections(struct Client *cptr) {}
void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...) {}
int log_inassert;
void debug(int level, const char *form, ...) {}   /* ircd_alloc.o, --enable-debug */

/** A QUIT, as s_bsd.c's matcher reads one: tags and a prefix allowed. */
static int is_quit(const char *line, void *ctx)
{
  const char *p = line;

  (*(int *)ctx)++;
  if (*p == '@')
    while (*p && *p != ' ')
      p++;
  while (*p == ' ')
    p++;
  if (*p == ':') {
    while (*p && *p != ' ')
      p++;
    while (*p == ' ')
      p++;
  }
  return 0 == strncmp(p, "QUIT", 4) && (p[4] == '\0' || p[4] == ' ');
}

static void put(struct DBuf *q, const char *s)
{
  assert_true(dbuf_put(q, s, strlen(s)));
}

static void finds_after_lines_and_keeps_queue(void **state)
{
  struct DBuf q = { 0, 0, 0 };
  char buf[64];
  unsigned int off = 99;
  int calls = 0;
  const char *data = "PRIVMSG #a :one\r\n@label=x PING :t\r\n:me QUIT :bye\r\nNICK z\r\n";

  put(&q, data);
  assert_int_equal(dbuf_find_line(&q, buf, sizeof(buf), is_quit, &calls, &off), 1);
  assert_int_equal(off, strstr(data, ":me QUIT") - data);
  assert_int_equal(calls, 3);
  assert_int_equal(DBufLength(&q), strlen(data));
  DBufClear(&q);
}

static void across_buffers(void **state)
{
  struct DBuf q = { 0, 0, 0 };
  static char filler[DBUF_SIZE * 2 + 7];
  char buf[64];
  unsigned int off = 0;
  int calls = 0;

  /* a run of short lines that pushes the QUIT across a buffer boundary */
  memset(filler, 'x', sizeof(filler) - 1);
  for (size_t i = 50; i < sizeof(filler) - 1; i += 51)
    filler[i] = '\n';
  filler[sizeof(filler) - 2] = '\n';
  put(&q, filler);
  put(&q, "QU");
  put(&q, "IT\n");
  assert_int_equal(dbuf_find_line(&q, buf, sizeof(buf), is_quit, &calls, &off), 1);
  assert_int_equal(off, sizeof(filler) - 1);
  DBufClear(&q);
}

static void incomplete_line_is_not_a_line(void **state)
{
  struct DBuf q = { 0, 0, 0 };
  char buf[64];
  unsigned int off = 0;
  int calls = 0;

  put(&q, "PRIVMSG #a :x\nQUIT :not yet ended");
  assert_int_equal(dbuf_find_line(&q, buf, sizeof(buf), is_quit, &calls, &off), 0);
  assert_int_equal(calls, 1);
  put(&q, "\r\n");
  assert_int_equal(dbuf_find_line(&q, buf, sizeof(buf), is_quit, &calls, &off), 1);
  assert_int_equal(off, 14);
  DBufClear(&q);
}

static void long_line_is_cut_not_overrun(void **state)
{
  struct DBuf q = { 0, 0, 0 };
  char buf[8];
  unsigned int off = 0;
  int calls = 0;

  /* a line longer than the scratch buffer: its start is matched, the
   * rest skipped, and the next line still found */
  put(&q, "PRIVMSG #a :a long line indeed\nQUIT\n");
  assert_int_equal(dbuf_find_line(&q, buf, sizeof(buf), is_quit, &calls, &off), 1);
  assert_int_equal(off, 31);
  assert_int_equal(calls, 2);
  DBufClear(&q);
}

static void empty_queue(void **state)
{
  struct DBuf q = { 0, 0, 0 };
  char buf[8];
  int calls = 0;

  assert_int_equal(dbuf_find_line(&q, buf, sizeof(buf), is_quit, &calls, NULL), 0);
  assert_int_equal(calls, 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(finds_after_lines_and_keeps_queue),
    cmocka_unit_test(across_buffers),
    cmocka_unit_test(incomplete_line_is_not_a_line),
    cmocka_unit_test(long_line_is_cut_not_overrun),
    cmocka_unit_test(empty_queue),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
