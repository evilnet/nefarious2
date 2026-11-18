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
static char all_tags[16384];      /* every tag region msgq_make saw, ' | '-joined */
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
/* Each line msgq_make() builds: its tag region and, for a server line
 * ("%s%C %s ..." or "%C %s ..."), its token.  The MsgBuf handed back is
 * the record itself, so msgq_add() can tell which line a link was sent. */
struct made_line {
  char tags[512];
  char tok[8];
};
static struct made_line made[64];
static int made_next;
struct MsgBuf *msgq_make(struct Client *dest, const char *format, ...)
{
  struct made_line *ml = &made[made_next++ % 64];
  va_list ap;
  (void)dest;
  lines_made++;
  last_tags[0] = '\0';
  memset(ml, 0, sizeof(*ml));
  va_start(ap, format);
  if (format[0] == '%' && format[1] == 's') {   /* "%s%:#C ..." = tag region first */
    ircd_strncpy(last_tags, va_arg(ap, const char *), sizeof(last_tags));
    ircd_strncpy(ml->tags, last_tags, sizeof(ml->tags));
    if (strncmp(format + 2, "%C %s ", 6) == 0) {
      (void)va_arg(ap, struct Client *);
      ircd_strncpy(ml->tok, va_arg(ap, const char *), sizeof(ml->tok));
    }
  } else if (strncmp(format, "%C %s ", 6) == 0) {
    (void)va_arg(ap, struct Client *);
    ircd_strncpy(ml->tok, va_arg(ap, const char *), sizeof(ml->tok));
  }
  va_end(ap);
  if (last_tags[0] && strlen(all_tags) + strlen(last_tags) + 4 < sizeof(all_tags)) {
    strcat(all_tags, last_tags);
    strcat(all_tags, " | ");
  }
  return (struct MsgBuf *)ml;
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
/* ...and its BATCH + line (send_batch_marker()), the same: ircd_snprintf()
 * below fails every format but the channel send's user prefix. */
/* The line each fake link was last queued (the dispatch cases). */
static struct MsgQ *sent_q[4];
static const struct made_line *sent_line[4];
void msgq_add(struct MsgQ *mq, struct MsgBuf *mb, int prio)
{
  int i;
  (void)prio;
  for (i = 0; i < 4; i++)
    if (sent_q[i] == mq) {
      sent_line[i] = (const struct made_line *)mb;
      return;
    }
}
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
/* For the channel send (the ,P hardening cases): a channel with no
 * members reaches only these. */
struct Client *LocalClientArray[MAXCONNECTIONS];
int HighestFd = -1;
int is_silenced(struct Client *sptr, struct Client *acptr, int ischanmsg)
{ (void)sptr; (void)acptr; (void)ischanmsg; return 0; }
int persistence_channel_visible(struct Client *cptr, const char *chname)
{ (void)cptr; (void)chname; return 1; }
struct Client *hSeekClient(const char *name, int TMask)
{ (void)name; (void)TMask; return NULL; }
int ircd_snprintf(struct Client *dest, char *buf, size_t buf_len,
                  const char *format, ...)
{
  /* The channel send's user-format prefix ("%%s%s", the ,P hardening
   * cases) is formatted; any other format -- a deferred labeled batch's
   * BATCH + line (send_batch_marker()), which no case here reaches --
   * still fails the case, as before. */
  va_list ap;
  int n;
  (void)dest;
  if (strcmp(format, "%C %s %v") == 0) {   /* send_s2s_untagged_fits() */
    struct Client *from;
    const char *tok;
    struct VarData *vd;
    va_list cp;
    va_start(ap, format);
    from = va_arg(ap, struct Client *);
    tok = va_arg(ap, const char *);
    vd = va_arg(ap, struct VarData *);
    va_end(ap);
    n = snprintf(buf, buf_len, "%s %s ", cli_yxx(from), tok);
    va_copy(cp, vd->vd_args);
    n += vsnprintf(buf + n, buf_len - n, vd->vd_format, cp);
    va_end(cp);
    return n;
  }
  if (strcmp(format, "%%s%s") != 0) {
    fail();
    return 0;
  }
  va_start(ap, format);
  n = vsnprintf(buf, buf_len, format, ap);
  va_end(ap);
  return n;
}

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
  all_tags[0] = '\0';
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

/* --- The status-message marks ,P / ,P<status> (#226) --------------- */

/* The formatter never places ,P: the channel send places each form's own
 * (s2s_tags_insert_seg), so an arm reaches no other line. */
static void test_format_never_places_statusmsg_mark(void **state)
{
  char buf[512];
  (void)state;
  sendcmdto_set_statusmsg("hello", 0);
  assert_non_null(format_s2s_tags_with_client(buf, sizeof(buf), NULL, "+x=a",
                                              NULL, 0));
  assert_null(strstr(buf, ",P"));
}

/* An arm that a line toward one link (the DM path), or the end-of-line
 * reset, passes is gone: a later wall send carries no status form. */
static void test_statusmsg_arm_cleared(void **state)
{
  static struct Channel chan;
  (void)state;
  memset(&chan, 0, sizeof(chan));
  strcpy(chan.chname, "#c");

  sendcmdto_set_statusmsg("hello", 0);
  sendcmdto_one_tags_with_client(&user, "PRIVMSG", "P", &link_legacy, NULL, NULL,
                                 "%s :%s", "x", "hello");
  sendcmdto_channel_butone_with_client_tags(&user, "WALLCHOPS", "WC", &chan, NULL,
                                            SKIP_DEAF | SKIP_BURST | SKIP_NONOPS,
                                            '\0', NULL, "%s :%s", "#c", "@ hello");
  assert_non_null(strstr(all_tags, "@A"));
  assert_null(strstr(all_tags, ",P"));

  sendcmdto_set_statusmsg("hello", 0);
  sendcmdto_reset_s2s_overrides();
  sendcmdto_channel_butone_with_client_tags(&user, "WALLCHOPS", "WC", &chan, NULL,
                                            SKIP_DEAF | SKIP_BURST | SKIP_NONOPS,
                                            '\0', NULL, "%s :%s", "#c", "@ hello");
  assert_null(strstr(all_tags, ",P"));
}

/* A channel send with no wall status filter never carries ,P, even with
 * the status-message PRIVMSG armed (hardening: today both arm sites sit
 * right before a wall send).  The control: the same arm with the wall's
 * SKIP_NONOPS does mark the S2S line, so the capture is live. */
static void test_ordinary_channel_send_drops_statusmsg_mark(void **state)
{
  static struct Channel chan;
  char buf[512];
  (void)state;
  memset(&chan, 0, sizeof(chan));
  strcpy(chan.chname, "#c");

  sendcmdto_set_statusmsg("hello", 0);
  sendcmdto_channel_butone_with_client_tags(&user, "PRIVMSG", "P", &chan, NULL,
                                            SKIP_DEAF | SKIP_BURST, '\0', NULL,
                                            "%s :%s", "#c", "hello");
  assert_non_null(strstr(all_tags, "@A"));          /* a tag region was built */
  assert_null(strstr(all_tags, ",P"));
  format_s2s_tags_with_client(buf, sizeof(buf), NULL, NULL, NULL, 0);
  assert_null(strstr(buf, ",P"));                   /* and nothing left armed */

  all_tags[0] = '\0';
  sendcmdto_set_statusmsg("hello", 0);
  sendcmdto_channel_butone_with_client_tags(&user, "WALLCHOPS", "WC", &chan, NULL,
                                            SKIP_DEAF | SKIP_BURST | SKIP_NONOPS,
                                            '\0', NULL, "%s :%s", "#c", "@ hello");
  assert_non_null(strstr(all_tags, ",P "));
}

/* The same through the variant with client tags: ,C stays, ,P does not. */
static void test_ordinary_channel_send_with_ctags_drops_statusmsg_mark(void **state)
{
  static struct Channel chan;
  (void)state;
  memset(&chan, 0, sizeof(chan));
  strcpy(chan.chname, "#c");

  sendcmdto_set_statusmsg("hello", 0);
  sendcmdto_channel_butone_with_client_tags(&user, "PRIVMSG", "P", &chan, NULL,
                                            SKIP_DEAF | SKIP_BURST, '\0', "+x=a",
                                            "%s :%s", "#c", "hello");
  assert_non_null(strstr(all_tags, ",C+x=a"));
  assert_null(strstr(all_tags, ",P"));
}

/* --- A status message as the PRIVMSG/NOTICE it is ('S' links) ------ */

/* A PRIVMSG armed for a wall send: the 'S' form marked ,P@ and the wall
 * line marked ,P, each before the terminal ,C, with one msgid. */
static void test_statusmsg_privmsg_both_forms(void **state)
{
  static struct Channel chan;
  const char *a, *b;
  (void)state;
  memset(&chan, 0, sizeof(chan));
  strcpy(chan.chname, "#c");

  sendcmdto_set_statusmsg("hello", 0);
  sendcmdto_channel_butone_with_client_tags(&user, "WALLCHOPS", "WC", &chan, NULL,
                                            SKIP_DEAF | SKIP_BURST | SKIP_NONOPS,
                                            '\0', "+x=a", "%s :%s", "#c", "@ hello");
  assert_non_null(strstr(all_tags, ",P@,C+x=a "));
  assert_non_null(strstr(all_tags, ",P,C+x=a "));
  /* same "@A<time><msgid>" head */
  a = strstr(all_tags, "@A");
  b = strstr(a + 1, "@A");
  assert_non_null(b);
  assert_int_equal(0, strncmp(a, b, 2 + 7 + 14));
}

/* A NOTICE: the 'S' form marked ,P%, the wall line carries no ,P -- the
 * wall line IS the NOTICE form toward every other link. */
static void test_statusmsg_notice_wall_line_unmarked(void **state)
{
  static struct Channel chan;
  (void)state;
  memset(&chan, 0, sizeof(chan));
  strcpy(chan.chname, "#c");

  sendcmdto_set_statusmsg("hello", 1);
  sendcmdto_channel_butone_with_client_tags(&user, "WALLHOPS", "WH", &chan, NULL,
                                            SKIP_DEAF | SKIP_BURST | SKIP_NONHOPS,
                                            '\0', NULL, "%s :%s", "#c", "% hello");
  assert_non_null(strstr(all_tags, ",P% "));
  assert_null(strstr(all_tags, ",P "));
  /* and nothing is left armed: the next wall send is the wall line alone */
  all_tags[0] = '\0';
  sendcmdto_channel_butone_with_client_tags(&user, "WALLHOPS", "WH", &chan, NULL,
                                            SKIP_DEAF | SKIP_BURST | SKIP_NONHOPS,
                                            '\0', NULL, "%s :%s", "#c", "% hello");
  assert_non_null(strstr(all_tags, "@A"));
  assert_null(strstr(all_tags, ",P"));
}

/* Armed, but the send has no wall status filter: neither form. */
static void test_statusmsg_notice_ordinary_send_unmarked(void **state)
{
  static struct Channel chan;
  (void)state;
  memset(&chan, 0, sizeof(chan));
  strcpy(chan.chname, "#c");

  sendcmdto_set_statusmsg("hello", 1);
  sendcmdto_channel_butone_with_client_tags(&user, "NOTICE", "O", &chan, NULL,
                                            SKIP_DEAF | SKIP_BURST, '\0', NULL,
                                            "%s :%s", "#c", "hello");
  assert_non_null(strstr(all_tags, "@A"));
  assert_null(strstr(all_tags, ",P"));
}

/* Arming one kind disarms the other: a NOTICE armed after a PRIVMSG
 * leaves no ,P for the wall line. */
static void test_statusmsg_arms_replace(void **state)
{
  static struct Channel chan;
  (void)state;
  memset(&chan, 0, sizeof(chan));
  strcpy(chan.chname, "#c");

  sendcmdto_set_statusmsg("hello", 0);
  sendcmdto_set_statusmsg("hello", 1);
  sendcmdto_channel_butone_with_client_tags(&user, "WALLVOICES", "WV", &chan, NULL,
                                            SKIP_DEAF | SKIP_BURST | SKIP_NONVOICES,
                                            '\0', NULL, "%s :%s", "#c", "+ hello");
  assert_non_null(strstr(all_tags, ",P+ "));
  assert_null(strstr(all_tags, ",P "));
}

/* --- Which link gets which line ------------------------------------ */

/* Three remote chanops, each behind its own link: one that announced 'S',
 * one IRCv3-aware without it, one legacy.  fds are set so the member loop
 * and send_buffer() reach msgq_add(), which records the line per link. */
static struct Client dl_link[3], dl_user[3];
static struct Connection dl_link_con[3];
static struct Membership dl_member[3];
static struct Channel dl_chan;

static void dispatch_setup(void)
{
  static struct Connection me_con;   /* send_buffer() counts cli_sendM(&me) */
  int i;
  memset(&me_con, 0, sizeof(me_con));
  cli_connect(&me) = &me_con;
  con_client(&me_con) = &me;
  memset(&dl_chan, 0, sizeof(dl_chan));
  strcpy(dl_chan.chname, "#c");
  for (i = 0; i < 3; i++) {
    mk_link(&dl_link[i], &dl_link_con[i], i < 2);
    cli_fd(&dl_link[i]) = 20 + i;
    memset(&dl_user[i], 0, sizeof(dl_user[i]));
    cli_status(&dl_user[i]) = STAT_USER;
    cli_connect(&dl_user[i]) = &dl_link_con[i];   /* cli_from() = the link */
    memset(&dl_member[i], 0, sizeof(dl_member[i]));
    dl_member[i].user = &dl_user[i];
    dl_member[i].channel = &dl_chan;
    dl_member[i].status = CHFL_CHANOP;
    dl_member[i].next_member = i < 2 ? &dl_member[i + 1] : NULL;
    sent_q[i] = &cli_sendQ(&dl_link[i]);
    sent_line[i] = NULL;
  }
  SetStatusMsgAware(&dl_link[0]);
  dl_chan.members = &dl_member[0];
}

static void dispatch_send(int notice, const char *ctags)
{
  if (notice)
    sendcmdto_set_statusmsg("hello", 1);
  else
    sendcmdto_set_statusmsg("hello", 0);
  sendcmdto_channel_butone_with_client_tags(&user, "WALLCHOPS", "WC", &dl_chan,
                                            NULL, SKIP_DEAF | SKIP_BURST | SKIP_NONOPS,
                                            '\0', ctags, "%s :%s", "#c", "@ hello");
}

/* A PRIVMSG: the 'S' link gets P marked ,P@; the IRCv3 link the wall
 * line marked ,P; the legacy link the bare wall line. */
static void test_statusmsg_dispatch_privmsg(void **state)
{
  (void)state;
  dispatch_setup();
  dispatch_send(0, NULL);
  assert_non_null(sent_line[0]);
  assert_string_equal(sent_line[0]->tok, "P");
  assert_non_null(strstr(sent_line[0]->tags, ",P@ "));
  assert_non_null(sent_line[1]);
  assert_string_equal(sent_line[1]->tok, "WC");
  assert_non_null(strstr(sent_line[1]->tags, ",P "));
  assert_non_null(sent_line[2]);
  assert_string_equal(sent_line[2]->tok, "WC");
  assert_string_equal(sent_line[2]->tags, "");
  /* one msgid for both tagged forms */
  assert_int_equal(0, strncmp(sent_line[0]->tags, sent_line[1]->tags, 2 + 7 + 14));
}

/* A NOTICE: O marked ,P@ toward 'S'; the unmarked wall line elsewhere. */
static void test_statusmsg_dispatch_notice(void **state)
{
  (void)state;
  dispatch_setup();
  dispatch_send(1, NULL);
  assert_string_equal(sent_line[0]->tok, "O");
  assert_non_null(strstr(sent_line[0]->tags, ",P@ "));
  assert_string_equal(sent_line[1]->tok, "WC");
  assert_null(strstr(sent_line[1]->tags, ",P"));
  assert_string_equal(sent_line[2]->tok, "WC");
  assert_string_equal(sent_line[2]->tags, "");
}

/* With client tags the tagged forms carry ,C after the mark. */
static void test_statusmsg_dispatch_ctags(void **state)
{
  (void)state;
  dispatch_setup();
  dispatch_send(0, "+x=a");
  assert_string_equal(sent_line[0]->tok, "P");
  assert_non_null(strstr(sent_line[0]->tags, ",P@,C+x=a "));
  assert_string_equal(sent_line[1]->tok, "WC");
  assert_non_null(strstr(sent_line[1]->tags, ",P,C+x=a "));
  assert_string_equal(sent_line[2]->tags, "");
}

/* P10_MESSAGE_TAGS off: no tag region, so every link, 'S' or not, gets
 * the bare wall line. */
static void test_statusmsg_dispatch_tags_off(void **state)
{
  int i;
  (void)state;
  tags_on = 0;
  dispatch_setup();
  dispatch_send(0, NULL);
  for (i = 0; i < 3; i++) {
    assert_non_null(sent_line[i]);
    assert_string_equal(sent_line[i]->tok, "WC");
    assert_string_equal(sent_line[i]->tags, "");
  }
  tags_on = 1;
}

/* --- A session echo line toward a server (#229) -------------------- */

#define BXE_ID "AzAAEG7Hq2LmAF"

/* sendcmdto_one_ctags() with token BX toward an IRCv3-aware link: the
 * line is led by @A<time><msgid>,C<client tags>, the time and msgid the
 * caller gave -- not a fresh mint, not a stash. */
static void test_bx_ctags_toward_v3_link(void **state)
{
  char want[128], tb[8];
  (void)state;
  sendcmdto_one_ctags(&me, "BOUNCER_TRANSFER", "BX", &link_v3,
                      1763000000123ULL, BXE_ID, "+draft/reply=x;+e=a,b",
                      "E %s %s %s %s %s :%s", "BzAAC", "AzAAAP", "bob",
                      BXE_ID, "fixed typo", "");
  inttobase64_64(tb, 1763000000123ULL, 7);
  snprintf(want, sizeof(want), "@A%s%s,C+draft/reply=x;+e=a,b ", tb, BXE_ID);
  assert_string_equal(last_tags, want);
}

/* Toward a legacy link, or with P10_MESSAGE_TAGS off: the bare line. */
static void test_bx_ctags_toward_legacy_link_is_bare(void **state)
{
  char buf[512];
  (void)state;
  sendcmdto_one_ctags(&me, "BOUNCER_TRANSFER", "BX", &link_legacy,
                      1763000000123ULL, BXE_ID, "+draft/reply=x",
                      "E %s :%s", "BzAAC", "hi");
  assert_string_equal(last_tags, "");
  tags_on = 0;
  sendcmdto_one_ctags(&me, "BOUNCER_TRANSFER", "BX", &link_v3,
                      1763000000123ULL, BXE_ID, "+draft/reply=x",
                      "E %s :%s", "BzAAC", "hi");
  assert_string_equal(last_tags, "");
  tags_on = 1;
  /* and nothing is left armed for the next line */
  format_s2s_tags_with_client(buf, sizeof(buf), NULL, NULL, NULL, 0);
  assert_null(strstr(buf, BXE_ID));
}

/* No client tags, or a msgid of another shape ("*"): the bare line,
 * as before -- the receiver reads the time from the msgid. */
static void test_bx_ctags_without_tags_is_bare(void **state)
{
  (void)state;
  sendcmdto_one_ctags(&me, "BOUNCER_TRANSFER", "BX", &link_v3,
                      1763000000123ULL, BXE_ID, NULL, "E %s :%s", "BzAAC", "hi");
  assert_string_equal(last_tags, "");
  sendcmdto_one_ctags(&me, "BOUNCER_TRANSFER", "BX", &link_v3,
                      1763000000123ULL, BXE_ID, "", "E %s :%s", "BzAAC", "hi");
  assert_string_equal(last_tags, "");
  sendcmdto_one_ctags(&me, "BOUNCER_TRANSFER", "BX", &link_v3,
                      1763000000123ULL, "*", "+x", "E %s :%s", "BzAAC", "hi");
  assert_string_equal(last_tags, "");
}

/* sendcmdto_one_region(): the session echo's sender (BX E, the BX M
 * start line, their middle-hop forwards).  The region goes whenever the
 * link takes S2S tags and the msgid is a compact one -- with or without
 * client tags -- so the receiver reads the line's time from the region
 * (its own clock's correction, #163) and never from the msgid.  ,C only
 * with tags. */
static void test_bx_region_without_tags_toward_v3_link(void **state)
{
  char want[128], tb[8];
  (void)state;
  sendcmdto_one_region(&me, "BOUNCER_TRANSFER", "BX", &link_v3,
                       1763000000123ULL, BXE_ID, NULL,
                       "E %s :%s", "BzAAC", "hi");
  inttobase64_64(tb, 1763000000123ULL, 7);
  snprintf(want, sizeof(want), "@A%s%s ", tb, BXE_ID);
  assert_string_equal(last_tags, want);
  sendcmdto_one_region(&me, "BOUNCER_TRANSFER", "BX", &link_v3,
                       1763000000123ULL, BXE_ID, "",
                       "E %s :%s", "BzAAC", "hi");
  assert_string_equal(last_tags, want);
}

static void test_bx_region_with_tags_as_ctags(void **state)
{
  char want[128], tb[8];
  (void)state;
  sendcmdto_one_region(&me, "BOUNCER_TRANSFER", "BX", &link_v3,
                       1763000000123ULL, BXE_ID, "+draft/reply=x;+e=a,b",
                       "E %s :%s", "BzAAC", "hi");
  inttobase64_64(tb, 1763000000123ULL, 7);
  snprintf(want, sizeof(want), "@A%s%s,C+draft/reply=x;+e=a,b ", tb, BXE_ID);
  assert_string_equal(last_tags, want);
}

/* Toward a legacy link, with tags off, or for a "*" msgid: the bare
 * line, and nothing left armed for the next one. */
static void test_bx_region_bare_cases(void **state)
{
  char buf[512];
  (void)state;
  sendcmdto_one_region(&me, "BOUNCER_TRANSFER", "BX", &link_legacy,
                       1763000000123ULL, BXE_ID, NULL, "E %s :%s", "BzAAC", "hi");
  assert_string_equal(last_tags, "");
  sendcmdto_one_region(&me, "BOUNCER_TRANSFER", "BX", &link_legacy,
                       1763000000123ULL, BXE_ID, "+x", "E %s :%s", "BzAAC", "hi");
  assert_string_equal(last_tags, "");
  tags_on = 0;
  sendcmdto_one_region(&me, "BOUNCER_TRANSFER", "BX", &link_v3,
                       1763000000123ULL, BXE_ID, NULL, "E %s :%s", "BzAAC", "hi");
  assert_string_equal(last_tags, "");
  tags_on = 1;
  sendcmdto_one_region(&me, "BOUNCER_TRANSFER", "BX", &link_v3,
                       1763000000123ULL, "*", NULL, "E %s :%s", "BzAAC", "hi");
  assert_string_equal(last_tags, "");
  sendcmdto_one_region(&me, "BOUNCER_TRANSFER", "BX", &link_v3,
                       1763000000123ULL, "*", "+x", "E %s :%s", "BzAAC", "hi");
  assert_string_equal(last_tags, "");
  sendcmdto_one_region(&me, "BOUNCER_TRANSFER", "BX", &link_v3,
                       1763000000123ULL, NULL, NULL, "E %s :%s", "BzAAC", "hi");
  assert_string_equal(last_tags, "");
  format_s2s_tags_with_client(buf, sizeof(buf), NULL, NULL, NULL, 0);
  assert_null(strstr(buf, BXE_ID));
}

/* The federated history line (CH R, and its middle hop) keeps
 * sendcmdto_one_ctags(): no client tags, no region -- unchanged by the
 * session echo's sender. */
static void test_ch_r_without_tags_stays_bare(void **state)
{
  char want[128], tb[8];
  (void)state;
  sendcmdto_one_ctags(&me, "CHATHISTORY", "CH", &link_v3,
                      1763000000123ULL, BXE_ID, NULL,
                      "R %s %s :%s", "#c", BXE_ID, "row");
  assert_string_equal(last_tags, "");
  sendcmdto_one_ctags(&me, "CHATHISTORY", "CH", &link_v3,
                      1763000000123ULL, BXE_ID, "+x=1",
                      "R %s %s :%s", "#c", BXE_ID, "row");
  inttobase64_64(tb, 1763000000123ULL, 7);
  snprintf(want, sizeof(want), "@A%s%s,C+x=1 ", tb, BXE_ID);
  assert_string_equal(last_tags, want);
}

/* The session echo's sends sit inside an armed client event (the local
 * members' copies, the sender's own echo): a BX line between them must
 * leave it armed. */
static void test_bx_ctags_keeps_the_client_event(void **state)
{
  (void)state;
  sendcmdto_set_client_event(BXE_ID, 1763000000123ULL);
  sendcmdto_one_ctags(&me, "BOUNCER_TRANSFER", "BX", &link_v3,
                      1763000000123ULL, BXE_ID, "+x", "E %s :%s", "BzAAC", "hi");
  assert_string_equal(client_msgid_override, BXE_ID);
  assert_true(client_event_ms == 1763000000123ULL);
  sendcmdto_one_ctags(&me, "BOUNCER_TRANSFER", "BX", &link_v3,
                      1763000000123ULL, BXE_ID, NULL, "E %s :%s", "BzAAC", "hi");
  assert_string_equal(client_msgid_override, BXE_ID);
  sendcmdto_set_client_msgid(NULL);
}

/* 4094 bytes of client tags: the whole region, never cut. */
static void test_bx_ctags_full_size_is_whole(void **state)
{
  static char big[4095];
  (void)state;
  memset(big, 'a', sizeof(big) - 1);
  big[0] = '+';
  big[1] = 'k';
  big[2] = '=';
  big[sizeof(big) - 1] = '\0';
  sendcmdto_one_ctags(&me, "BOUNCER_TRANSFER", "BX", &link_v3,
                      1763000000123ULL, BXE_ID, big, "E %s :%s", "BzAAC", "hi");
  assert_int_equal(strlen(last_tags), 2 + 7 + 14 + 2 + 4094 + 1);
  assert_string_equal(last_tags + 2 + 7 + 14 + 2 + 4094, " ");
}

/* The BX M start line's fit check measures the text too (#229 review):
 * the check and the send share BXM_START_CTAGS_FMT, so a format one
 * conversion short -- the text left unmeasured -- would pass a line that
 * is cut on the wire.  444 bytes of tags fit with a short text; with a
 * 100-byte text the same line is over 510. */
static int bxm_fits(const char *ctags, const char *text)
{
  return send_s2s_untagged_fits(&me, "BX", BXM_START_CTAGS_FMT,
                                "AAB17946704930", "ACAAB", "AB", "AAB", "P",
                                "rr", BXE_ID, ctags, text);
}

static void test_bxm_start_fit_measures_the_text(void **state)
{
  static char ctags[445], text[101];
  (void)state;
  memset(ctags, 'z', sizeof(ctags) - 1);
  memcpy(ctags, "+k=", 3);
  memset(text, 't', sizeof(text) - 1);
  assert_true(bxm_fits(ctags, "t"));
  assert_false(bxm_fits(ctags, text));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(test_bxm_start_fit_measures_the_text, setup),
    cmocka_unit_test_setup(test_bx_ctags_toward_v3_link, setup),
    cmocka_unit_test_setup(test_bx_ctags_toward_legacy_link_is_bare, setup),
    cmocka_unit_test_setup(test_bx_ctags_without_tags_is_bare, setup),
    cmocka_unit_test_setup(test_bx_ctags_keeps_the_client_event, setup),
    cmocka_unit_test_setup(test_bx_region_without_tags_toward_v3_link, setup),
    cmocka_unit_test_setup(test_bx_region_with_tags_as_ctags, setup),
    cmocka_unit_test_setup(test_bx_region_bare_cases, setup),
    cmocka_unit_test_setup(test_ch_r_without_tags_stays_bare, setup),
    cmocka_unit_test_setup(test_bx_ctags_full_size_is_whole, setup),
    cmocka_unit_test_setup(test_ordinary_channel_send_drops_statusmsg_mark, setup),
    cmocka_unit_test_setup(test_ordinary_channel_send_with_ctags_drops_statusmsg_mark, setup),
    cmocka_unit_test_setup(test_statusmsg_privmsg_both_forms, setup),
    cmocka_unit_test_setup(test_statusmsg_notice_wall_line_unmarked, setup),
    cmocka_unit_test_setup(test_statusmsg_notice_ordinary_send_unmarked, setup),
    cmocka_unit_test_setup(test_statusmsg_arms_replace, setup),
    cmocka_unit_test_setup(test_statusmsg_dispatch_privmsg, setup),
    cmocka_unit_test_setup(test_statusmsg_dispatch_notice, setup),
    cmocka_unit_test_setup(test_statusmsg_dispatch_ctags, setup),
    cmocka_unit_test_setup(test_statusmsg_dispatch_tags_off, setup),
    cmocka_unit_test_setup(test_format_never_places_statusmsg_mark, setup),
    cmocka_unit_test_setup(test_statusmsg_arm_cleared, setup),
    cmocka_unit_test_setup(test_format_places_and_consumes_mark, setup),
    cmocka_unit_test_setup(test_no_mark_unless_armed, setup),
    cmocka_unit_test_setup(test_send_to_v3_link_carries_mark, setup),
    cmocka_unit_test_setup(test_legacy_link_clears_mark, setup),
    cmocka_unit_test_setup(test_tags_off_clears_mark, setup),
    cmocka_unit_test_setup(test_reset_clears_mark, setup),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
