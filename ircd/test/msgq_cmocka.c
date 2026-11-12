/*
 * msgq_cmocka.c - msgq_make()'s cut of the body of a line
 *
 * msgq_vmake() keeps everything after the tag region of a line within
 * 510 bytes for a client (the whole of an untagged line, the rest of a
 * tagged one -- message-tags moves only the tags out of the 512-byte
 * limit), and within 510 / 512 for a server (untagged / tagged), each
 * cut at a UTF-8 boundary by ircd_line_body_clamp().  The client branch
 * is the backstop under the relay's origin cut (ircd_relay.c
 * relay_cut_text): a message cut at its origin is never cut again here.
 *
 * Links the real msgq.o, ircd_snprintf.o, ircd_string.o and
 * ircd_alloc.o; the rest of the server is stubbed below.
 */
#include "config.h"

#include "client.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "msgq.h"
#include "send.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

/* --- stubs for what msgq.c reaches outside the files linked --- */

int feature_bool(enum Feature feat) { (void)feat; return 0; }
int feature_int(enum Feature feat) { (void)feat; return 1 << 20; } /* BUFFERPOOL */
void flush_connections(struct Client *cptr) { (void)cptr; }
void kill_highest_sendq(int servers_too) { (void)servers_too; }
void server_panic(const char *message) { fail_msg("server_panic: %s", message); }
int send_reply(struct Client *to, int reply, ...) { (void)to; (void)reply; return 0; }

/* --- helpers --- */

static char line[9000];

/* Build line = head + n copies of the bytes at unit (unit_len each). */
static size_t build(const char *head, const char *unit, size_t unit_len, size_t n)
{
  size_t h = strlen(head), i;

  memcpy(line, head, h);
  for (i = 0; i < n; i++)
    memcpy(line + h + i * unit_len, unit, unit_len);
  line[h + n * unit_len] = '\0';
  return h + n * unit_len;
}

/* The bytes of mb without the trailing CRLF, and their length. */
static unsigned int made(struct MsgBuf *mb, const char **data)
{
  unsigned int len;

  msgq_buf_data(mb, data, &len);
  assert_true(len >= 2);
  assert_memory_equal(*data + len - 2, "\r\n", 2);
  return len - 2;
}

/* Bytes after the tag region (the whole line when it has none). */
static unsigned int after_tags(const char *data, unsigned int len)
{
  const char *sp;

  if (data[0] != '@')
    return len;
  sp = memchr(data, ' ', len);
  return sp ? len - (unsigned int)(sp + 1 - data) : 0;
}

/* --- client lines (dest is NULL or a user) --- */

static void test_client_untagged_cut_at_510(void **state)
{
  const char *data;
  struct MsgBuf *mb;
  size_t n = build(":sender!u@127.0.0.1 PRIVMSG #t :", "a", 1, 498); /* 530 */
  (void)state;

  mb = msgq_make(0, "%s", line);
  assert_int_equal(510, made(mb, &data));
  assert_memory_equal(data, line, 510);
  assert_true(n > 510);
  msgq_clean(mb);
}

static void test_client_tagged_body_cut_at_510(void **state)
{
  /* The PR's case: a tagged line used to keep a 530-byte body. */
  const char *data;
  unsigned int len;
  struct MsgBuf *mb;
  const char *tags = "@time=2026-11-12T00:00:00.000Z;msgid=ABAAAaHQPd0OBB ";
  (void)state;

  build(":sender!u@127.0.0.1 PRIVMSG #t :", "a", 1, 498);
  mb = msgq_make(0, "%s%s", tags, line);
  len = made(mb, &data);
  assert_int_equal(510, after_tags(data, len));
  assert_int_equal(strlen(tags) + 510, len);
  /* The tag region is whole. */
  assert_memory_equal(data, tags, strlen(tags));
  msgq_clean(mb);
}

static void test_client_tagged_and_untagged_read_the_same(void **state)
{
  const char *d1, *d2;
  unsigned int l1, l2;
  struct MsgBuf *m1, *m2;
  (void)state;

  build(":sender!u@127.0.0.1 PRIVMSG #t :", "\342\202\254", 3, 166); /* euro x166 */
  m1 = msgq_make(0, "%s", line);
  m2 = msgq_make(0, "@time=x %s", line);
  l1 = made(m1, &d1);
  l2 = made(m2, &d2);
  assert_int_equal(l1, after_tags(d2, l2));
  assert_memory_equal(d1, d2 + strlen("@time=x "), l1);
  msgq_clean(m1);
  msgq_clean(m2);
}

static void test_client_utf8_cut_offsets(void **state)
{
  /* A 32-byte head + a run of U+20AC: the 510 cut lands at offset
   * (510 - 32 - pad) mod 3 of a character for pad = 0, 1, 2 ASCII bytes
   * ahead of the run; the line ends on a whole character every time. */
  static const unsigned int want[3] = { 509, 510, 508 };
  int pad;
  (void)state;

  for (pad = 0; pad < 3; pad++) {
    char head[64];
    const char *data;
    unsigned int len;
    struct MsgBuf *mb;

    snprintf(head, sizeof(head), ":sender!u@127.0.0.1 PRIVMSG #t :%.*s", pad, "xx");
    build(head, "\342\202\254", 3, 166);
    mb = msgq_make(0, "@t %s", line);
    len = made(mb, &data);
    assert_int_equal(want[pad], after_tags(data, len));
    /* The last byte kept is the end of a euro sign (AC). */
    assert_int_equal(0xAC, (unsigned char)data[len - 1]);
    msgq_clean(mb);
  }
}

static void test_client_line_that_fits_is_whole(void **state)
{
  /* A line the relay already cut at its origin is never cut again. */
  const char *data;
  struct MsgBuf *mb;
  size_t n = build(":sender!u@127.0.0.1 PRIVMSG #t :", "a", 1, 478); /* 510 */
  (void)state;

  mb = msgq_make(0, "@time=x %s", line);
  assert_int_equal(strlen("@time=x ") + n, made(mb, &data));
  msgq_clean(mb);
  mb = msgq_make(0, "%s", line);
  assert_int_equal(n, made(mb, &data));
  msgq_clean(mb);
}

static void test_client_dest_user_same_as_null(void **state)
{
  /* A registered user as the destination takes the client branch too. */
  struct Client user;
  const char *data;
  unsigned int len;
  struct MsgBuf *mb;
  (void)state;

  memset(&user, 0, sizeof(user));
  cli_status(&user) = STAT_USER;
  build(":sender!u@127.0.0.1 PRIVMSG #t :", "a", 1, 498);
  mb = msgq_make(&user, "@t %s", line);
  len = made(mb, &data);
  assert_int_equal(510, after_tags(data, len));
  msgq_clean(mb);
}

/* --- server lines: unchanged by the client cut --- */

static void test_server_untagged_510_tagged_512(void **state)
{
  struct Client srv;
  const char *data;
  unsigned int len;
  struct MsgBuf *mb;
  (void)state;

  memset(&srv, 0, sizeof(srv));
  cli_status(&srv) = STAT_SERVER;
  build("ABAAA P #t :", "a", 1, 600);
  mb = msgq_make(&srv, "%s", line);
  assert_int_equal(510, made(mb, &data));
  msgq_clean(mb);
  mb = msgq_make(&srv, "@AxyzABAAAaHQ %s", line);
  len = made(mb, &data);
  assert_int_equal(512, after_tags(data, len));
  msgq_clean(mb);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_client_untagged_cut_at_510),
    cmocka_unit_test(test_client_tagged_body_cut_at_510),
    cmocka_unit_test(test_client_tagged_and_untagged_read_the_same),
    cmocka_unit_test(test_client_utf8_cut_offsets),
    cmocka_unit_test(test_client_line_that_fits_is_whole),
    cmocka_unit_test(test_client_dest_user_same_as_null),
    cmocka_unit_test(test_server_untagged_510_tagged_512),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
