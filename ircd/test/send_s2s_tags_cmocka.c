/*
 * send_s2s_tags_cmocka.c - the S2S compact tag region send.c builds, for
 * the multiline fallback mark ,F<msgid>:
 *   - format_s2s_tags_with_client() emits ,F after ,M and before ,C (,C is
 *     terminal), from the armed override, and consumes the override;
 *   - sendcmdto_one_tags_with_client() puts it on the line toward an
 *     IRCv3-aware link, and clears it when the link is legacy or
 *     P10_MESSAGE_TAGS is off, so it never stamps a later line.
 *
 * Includes the real send.c, compiled with -ffunction-sections and linked
 * with --gc-sections: only what these functions reach is kept, and that
 * world is stubbed below.  msgq_make() records the tag region a line was
 * built with; the fake link's fd is -1, so send_buffer() queues nothing.
 */
#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wformat-truncation"
#include "../send.c"
#pragma GCC diagnostic pop

/* ------------------------------------------------------------------ */
/* The world around send.c                                             */
/* ------------------------------------------------------------------ */

struct Client me;
unsigned long MsgIdCounter;
int log_inassert;
static int tags_on = 1;
static char last_tags[8192];
static int lines_made;
static struct HLC hlc = { 1700000000000ULL, 1, 1 };

int feature_bool(enum Feature feat)
{
  return feat == FEAT_P10_MESSAGE_TAGS ? tags_on : 0;
}
const struct HLC *hlc_global(void) { return &hlc; }
struct HLC hlc_global_event(void) { hlc.logical++; return hlc; }
int bounce_hold_mark_valid(char mark) { return mark == 'h' || mark == 'p' || mark == 'n'; }
const char *inttobase64_64(char *buf, uint64_t v, unsigned int count)
{
  static const char b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]";
  buf[count] = '\0';
  while (count > 0) {
    buf[--count] = b64[v & 63];
    v >>= 6;
  }
  return buf;
}
char *ircd_strncpy(char *dest, const char *src, size_t len)
{
  if (len) {
    strncpy(dest, src, len - 1);
    dest[len - 1] = '\0';
  }
  return dest;
}
struct MsgBuf *msgq_make(struct Client *dest, const char *format, ...)
{
  static struct MsgBuf *dummy;
  va_list ap;
  (void)dest;
  lines_made++;
  last_tags[0] = '\0';
  if (format[0] == '%' && format[1] == 's') {   /* "%s%:#C ..." = tag region first */
    va_start(ap, format);
    ircd_strncpy(last_tags, va_arg(ap, const char *), sizeof(last_tags));
    va_end(ap);
  }
  if (!dummy)
    dummy = calloc(1, 256);
  return dummy;
}
void msgq_clean(struct MsgBuf *mb) { (void)mb; }
/* send_buffer()'s deferred labeled batch (send.c, labeled_batch_defer())
 * holds lines through these; no case here defers one, so none is reached. */
void msgq_buf_data(struct MsgBuf *mb, const char **data, unsigned int *len)
{
  (void)mb;
  *data = "";
  *len = 0;
  fail();
}
void *DoMalloc(size_t len, const char *type, const char *file, int line)
{
  (void)len; (void)type; (void)file; (void)line;
  fail();
  return NULL;
}
/* ...and its BATCH + line (send_batch_marker()), the same. */
int ircd_snprintf(struct Client *dest, char *buf, size_t buf_len,
                  const char *format, ...)
{
  (void)dest; (void)buf; (void)buf_len; (void)format;
  fail();
  return 0;
}
void msgq_add(struct MsgQ *mq, struct MsgBuf *mb, int prio) { (void)mq; (void)mb; (void)prio; }
void msgq_delete(struct MsgQ *mq, unsigned int length) { (void)mq; (void)length; }
void dbuf_delete(struct DBuf *dyn, unsigned int length) { (void)dyn; (void)length; }
void client_drop_sendq(struct Connection *con) { (void)con; }
void client_add_sendq(struct Connection *con, struct Connection **con_p) { (void)con; (void)con_p; }
unsigned int get_sendq(struct Client *cptr) { (void)cptr; return 1u << 30; }
unsigned int deliver_it(struct Client *cptr, struct MsgQ *buf) { (void)cptr; (void)buf; return 0; }
int ws_flush_txrem(struct Client *cptr, unsigned int *wrote_out) { (void)cptr; (void)wrote_out; return 0; }
void update_write(struct Client *cptr) { (void)cptr; }
void debug(int level, const char *form, ...) { (void)level; (void)form; }
void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{ (void)subsys; (void)severity; (void)flags; (void)fmt; }
struct ConfItem *find_conf_byhost(struct SLink *lp, const char *host, int statmask)
{ (void)lp; (void)host; (void)statmask; return NULL; }

/* ------------------------------------------------------------------ */
/* A link and a client behind us                                        */
/* ------------------------------------------------------------------ */

static struct Client link_v3, link_legacy, user;
static struct Connection link_v3_con, link_legacy_con, user_con;
static struct User user_user;

static void mk_link(struct Client *c, struct Connection *con, int v3)
{
  memset(c, 0, sizeof(*c));
  memset(con, 0, sizeof(*con));
  cli_connect(c) = con;
  con_client(con) = c;
  cli_status(c) = STAT_SERVER;
  cli_fd(c) = -1;                       /* send_buffer() queues nothing */
  if (v3)
    SetIRCv3Aware(c);
}

static int setup(void **state)
{
  (void)state;
  memset(&me, 0, sizeof(me));
  cli_status(&me) = STAT_ME;
  strcpy(cli_yxx(&me), "AB");
  mk_link(&link_v3, &link_v3_con, 1);
  mk_link(&link_legacy, &link_legacy_con, 0);
  memset(&user, 0, sizeof(user));
  memset(&user_con, 0, sizeof(user_con));
  cli_connect(&user) = &user_con;
  con_client(&user_con) = &user;
  cli_status(&user) = STAT_USER;
  cli_user(&user) = &user_user;
  strcpy(cli_name(&user), "u");
  tags_on = 1;
  sendcmdto_reset_s2s_overrides();
  return 0;
}

/* ,F after ,M, before the terminal ,C; consumed by the format. */
static void test_format_places_and_consumes_mark(void **state)
{
  char buf[512];
  (void)state;
  sendcmdto_set_s2s_ml('+', "ref1");
  sendcmdto_set_s2s_fallback("ABAAAaHRNCiimg");
  assert_non_null(format_s2s_tags_with_client(buf, sizeof(buf), NULL, "+x=a,b",
                                              NULL, 0));
  assert_non_null(strstr(buf, ",M+ref1,FABAAAaHRNCiimg,C+x=a,b "));
  assert_non_null(format_s2s_tags_with_client(buf, sizeof(buf), NULL, NULL,
                                              NULL, 0));
  assert_null(strstr(buf, ",F"));
}

static void test_no_mark_unless_armed(void **state)
{
  char buf[512];
  (void)state;
  assert_non_null(format_s2s_tags_with_client(buf, sizeof(buf), NULL, "+x=a",
                                              NULL, 0));
  assert_null(strstr(buf, ",F"));
  sendcmdto_set_s2s_fallback("");                      /* empty disarms */
  format_s2s_tags_with_client(buf, sizeof(buf), NULL, NULL, NULL, 0);
  assert_null(strstr(buf, ",F"));
}

/* Toward an IRCv3-aware link the line carries it. */
static void test_send_to_v3_link_carries_mark(void **state)
{
  (void)state;
  sendcmdto_set_s2s_fallback("ABAAAaHRNCiimg");
  sendcmdto_one_tags_with_client(&user, "PRIVMSG", "P", &link_v3, NULL, NULL,
                                 "%s :%s", "x", "hello");
  assert_non_null(strstr(last_tags, ",FABAAAaHRNCiimg "));
}

/* Toward a legacy link: the bare line, and the mark does not survive to
 * stamp the next line. */
static void test_legacy_link_clears_mark(void **state)
{
  char buf[512];
  (void)state;
  sendcmdto_set_s2s_fallback("ABAAAaHRNCiimg");
  sendcmdto_one_tags_with_client(&user, "PRIVMSG", "P", &link_legacy, NULL, NULL,
                                 "%s :%s", "x", "hello");
  assert_string_equal(last_tags, "");
  format_s2s_tags_with_client(buf, sizeof(buf), NULL, NULL, NULL, 0);
  assert_null(strstr(buf, ",F"));
}

/* P10_MESSAGE_TAGS off: likewise. */
static void test_tags_off_clears_mark(void **state)
{
  char buf[512];
  (void)state;
  tags_on = 0;
  sendcmdto_set_s2s_fallback("ABAAAaHRNCiimg");
  sendcmdto_one_tags_with_client(&user, "PRIVMSG", "P", &link_v3, NULL, NULL,
                                 "%s :%s", "x", "hello");
  assert_string_equal(last_tags, "");
  tags_on = 1;
  format_s2s_tags_with_client(buf, sizeof(buf), NULL, NULL, NULL, 0);
  assert_null(strstr(buf, ",F"));
}

/* The end-of-line reset clears it too. */
static void test_reset_clears_mark(void **state)
{
  char buf[512];
  (void)state;
  sendcmdto_set_s2s_fallback("ABAAAaHRNCiimg");
  sendcmdto_reset_s2s_overrides();
  format_s2s_tags_with_client(buf, sizeof(buf), NULL, NULL, NULL, 0);
  assert_null(strstr(buf, ",F"));
}

/* --- The status-message PRIVMSG mark ,P (#226) --------------------- */

/* ,P carries no data, comes after ,F and before the terminal ,C, and is
 * consumed by the format that places it. */
static void test_statusmsg_mark_placed_and_consumed(void **state)
{
  char buf[512];
  (void)state;
  sendcmdto_set_statusmsg_privmsg("hello");
  assert_non_null(format_s2s_tags_with_client(buf, sizeof(buf), NULL, "+x=a,b",
                                              NULL, 0));
  assert_non_null(strstr(buf, ",P,C+x=a,b "));
  assert_non_null(format_s2s_tags_with_client(buf, sizeof(buf), NULL, NULL,
                                              NULL, 0));
  assert_null(strstr(buf, ",P"));
}

/* Without client tags it ends the region. */
static void test_statusmsg_mark_alone(void **state)
{
  char buf[512];
  (void)state;
  sendcmdto_set_statusmsg_privmsg("hello");
  assert_non_null(format_s2s_tags(buf, sizeof(buf), NULL, NULL, 0));
  assert_int_equal(0, strcmp(buf + strlen(buf) - 3, ",P "));
}

/* Every segment at once, in the documented order:
 * ,S<sessid>,H<mark>,M<flag><ref>,F<msgid>,P,C<client tags>. */
static void test_statusmsg_mark_order_with_every_segment(void **state)
{
  char buf[512];
  (void)state;
  sendcmdto_set_s2s_sessid("sess1");
  sendcmdto_set_s2s_held('p');
  sendcmdto_set_s2s_ml('+', "ref1");
  sendcmdto_set_s2s_fallback("ABAAAaHRNCiimg");
  sendcmdto_set_statusmsg_privmsg("hello");
  assert_non_null(format_s2s_tags_with_client(buf, sizeof(buf), NULL, "+x=a",
                                              NULL, 0));
  assert_non_null(strstr(buf, ",Ssess1,Hp,M+ref1,FABAAAaHRNCiimg,P,C+x=a "));
}

static void test_no_statusmsg_mark_unless_armed(void **state)
{
  char buf[512];
  (void)state;
  assert_non_null(format_s2s_tags_with_client(buf, sizeof(buf), NULL, "+x=a",
                                              NULL, 0));
  assert_null(strstr(buf, ",P"));
  sendcmdto_set_statusmsg_privmsg(NULL);               /* NULL disarms */
  format_s2s_tags_with_client(buf, sizeof(buf), NULL, NULL, NULL, 0);
  assert_null(strstr(buf, ",P"));
  sendcmdto_set_statusmsg_privmsg("");                 /* so does "" */
  format_s2s_tags_with_client(buf, sizeof(buf), NULL, NULL, NULL, 0);
  assert_null(strstr(buf, ",P"));
}

/* A line toward one link (the DM path) never carries it: armed for a
 * channel send only, and cleared by a send that does not use it. */
static void test_one_send_clears_statusmsg_mark(void **state)
{
  char buf[512];
  (void)state;
  sendcmdto_set_statusmsg_privmsg("hello");
  sendcmdto_one_tags_with_client(&user, "PRIVMSG", "P", &link_legacy, NULL, NULL,
                                 "%s :%s", "x", "hello");
  format_s2s_tags_with_client(buf, sizeof(buf), NULL, NULL, NULL, 0);
  assert_null(strstr(buf, ",P"));
}

/* The end-of-line reset clears it, with P10_MESSAGE_TAGS off too (the
 * format returns before consuming anything then). */
static void test_reset_clears_statusmsg_mark(void **state)
{
  char buf[512];
  (void)state;
  tags_on = 0;
  sendcmdto_set_statusmsg_privmsg("hello");
  assert_null(format_s2s_tags_with_client(buf, sizeof(buf), NULL, NULL, NULL, 0));
  tags_on = 1;
  sendcmdto_reset_s2s_overrides();
  format_s2s_tags_with_client(buf, sizeof(buf), NULL, NULL, NULL, 0);
  assert_null(strstr(buf, ",P"));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(test_statusmsg_mark_placed_and_consumed, setup),
    cmocka_unit_test_setup(test_statusmsg_mark_alone, setup),
    cmocka_unit_test_setup(test_statusmsg_mark_order_with_every_segment, setup),
    cmocka_unit_test_setup(test_no_statusmsg_mark_unless_armed, setup),
    cmocka_unit_test_setup(test_one_send_clears_statusmsg_mark, setup),
    cmocka_unit_test_setup(test_reset_clears_statusmsg_mark, setup),
    cmocka_unit_test_setup(test_format_places_and_consumes_mark, setup),
    cmocka_unit_test_setup(test_no_mark_unless_armed, setup),
    cmocka_unit_test_setup(test_send_to_v3_link_carries_mark, setup),
    cmocka_unit_test_setup(test_legacy_link_clears_mark, setup),
    cmocka_unit_test_setup(test_tags_off_clears_mark, setup),
    cmocka_unit_test_setup(test_reset_clears_mark, setup),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
