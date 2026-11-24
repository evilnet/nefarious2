/*
 * nickask_cmocka.c - a refusal answers a bouncer device's pending NICK
 * request (cli_nickask_ts) only when it refuses the nick asked for last.
 *
 * A numeric's parv[2] is the whole rest of the line ("x2 :Nickname is
 * already in use."), so the refused nick is its first word.  Includes
 * ../s_numeric.c; everything do_numeric() calls past the check is a stub.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "../s_numeric.c"
#include "ircd_log.h"
#include "ircd_string.h"

struct Client me;
time_t CurrentTime;
int log_inassert;
void log_write(enum LogSys s, enum LogLevel l, unsigned int f, const char *fmt, ...)
{ (void)s; (void)l; (void)f; (void)fmt; }

static struct Client *target;
struct Client *findNUser(const char *yxx) { (void)yxx; return target; }
struct Client *hSeekClient(const char *name, int mask) { (void)name; (void)mask; return target; }
struct Channel *hSeekChannel(const char *name) { (void)name; return NULL; }
struct BouncerSession *bounce_get_session(struct Client *c) { (void)c; return NULL; }
int feature_bool(enum Feature f) { (void)f; return 0; }
int ircd_snprintf(struct Client *d, char *buf, size_t len, const char *fmt, ...)
{
  va_list vl; int r; (void)d;
  va_start(vl, fmt); r = vsnprintf(buf, len, fmt, vl); va_end(vl);
  return r;
}
void fwd_label_close_batch(struct Client *a, struct ForwardedLabel *fl) { (void)a; (void)fl; }
void fwd_label_close_draining(struct Client *a) { (void)a; }
int fwd_label_exact_ends(struct ForwardedLabel *fl, int n) { (void)fl; (void)n; return 0; }
struct ForwardedLabel *fwd_label_find_for(struct Client *a, const char *m, struct Client **o)
{ (void)a; (void)m; if (o) *o = NULL; return NULL; }
struct ForwardedLabel *fwd_label_match(struct Client *a, int n, const char *p, struct Client *l,
                                       struct Client *s, struct Client **o, int *fit,
                                       struct Client **ask, int max, int *nask)
{ (void)a; (void)n; (void)p; (void)l; (void)s; (void)ask; (void)max;
  if (o) *o = NULL; if (fit) *fit = 0; if (nask) *nask = 0; return NULL; }
void fwd_label_open_batch(struct Client *a, struct ForwardedLabel *fl) { (void)a; (void)fl; }
int fwd_label_reply_ends(struct Client *o, struct ForwardedLabel *fl, int fit) { (void)o; (void)fl; (void)fit; return 0; }
struct Client *fwd_label_asker(struct Client *o, struct ForwardedLabel *fl) { (void)fl; return o; }
void sendcmdto_channel_butone(struct Client *f, const char *c, const char *t, struct Channel *to,
                              struct Client *one, unsigned int skip, unsigned char prefix,
                              const char *pattern, ...)
{ (void)f; (void)c; (void)t; (void)to; (void)one; (void)skip; (void)prefix; (void)pattern; }
void sendcmdto_one(struct Client *f, const char *c, const char *t, struct Client *to, const char *pattern, ...)
{ (void)f; (void)c; (void)t; (void)to; (void)pattern; }
void sendcmdto_one_tags(struct Client *f, const char *c, const char *t, struct Client *to, const char *pattern, ...)
{ (void)f; (void)c; (void)t; (void)to; (void)pattern; }
void sendcmdto_set_fwd_batch(const char *b) { (void)b; }
void sendcmdto_set_s2s_tags(uint64_t t, const char *m) { (void)t; (void)m; }

static struct Client server, device;
static struct Connection server_con, device_con;

static int setup(void **state)
{
  (void)state;
  memset(&server, 0, sizeof(server)); memset(&device, 0, sizeof(device));
  memset(&server_con, 0, sizeof(server_con)); memset(&device_con, 0, sizeof(device_con));
  cli_connect(&server) = &server_con; con_client(&server_con) = &server;
  cli_status(&server) = STAT_SERVER;
  cli_connect(&device) = &device_con; con_client(&device_con) = &device;
  cli_status(&device) = STAT_USER;
  SetBouncerAlias(&device);
  target = &device;
  return 0;
}

static void ask(const char *nick)
{
  ircd_strncpy(cli_nickask(&device), nick, sizeof(cli_nickask(&device)));
  cli_nickask_ts(&device) = 1000;
}

static void refuse(int numeric, char *rest)
{
  char *parv[4] = { "AB", "ABAAA", rest, NULL };
  do_numeric(numeric, 1, &server, &server, 3, parv);
}

static void refusal_of_asked_nick_answers_it(void **state)
{
  (void)state;
  ask("x2");
  refuse(ERR_NICKNAMEINUSE, "x2 :Nickname is already in use.");
  assert_int_equal(cli_nickask_ts(&device), 0);

  ask("x2");
  refuse(ERR_ERRONEUSNICKNAME, "x2 :Erroneous Nickname");
  assert_int_equal(cli_nickask_ts(&device), 0);

  ask("x2");
  refuse(ERR_NICKTOOFAST, "x2 x3 :Nick change too fast. Please wait 5 seconds.");
  assert_int_equal(cli_nickask_ts(&device), 0);
}

static void refusal_of_earlier_nick_leaves_it(void **state)
{
  (void)state;
  ask("x2");
  refuse(ERR_NICKNAMEINUSE, "x1 :Nickname is already in use.");
  assert_int_equal(cli_nickask_ts(&device), 1000);
  refuse(ERR_NICKNAMEINUSE, "x22 :Nickname is already in use.");
  assert_int_equal(cli_nickask_ts(&device), 1000);
  refuse(ERR_NICKNAMEINUSE, "x :Nickname is already in use.");
  assert_int_equal(cli_nickask_ts(&device), 1000);
  /* A case change is a request of its own: "X2" was asked before. */
  refuse(ERR_NICKNAMEINUSE, "X2 :Nickname is already in use.");
  assert_int_equal(cli_nickask_ts(&device), 1000);
}

static void channel_refusal_leaves_it(void **state)
{
  (void)state;
  ask("x2");
  refuse(ERR_BANNICKCHANGE, "#chan :Cannot change nickname while banned on channel");
  assert_int_equal(cli_nickask_ts(&device), 1000);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(refusal_of_asked_nick_answers_it, setup),
    cmocka_unit_test_setup(refusal_of_earlier_nick_leaves_it, setup),
    cmocka_unit_test_setup(channel_refusal_leaves_it, setup),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
