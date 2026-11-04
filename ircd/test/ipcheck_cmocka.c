/* ipcheck_cmocka.c - unit tests for ircd/IPcheck.c.
 *
 * The real IPcheck.c, compiled with assert() routed to mock_assert()
 * (mock_assert.h, see test/Makefile.in), against stubs for the few ircd
 * services it calls: features, timers, the clock and the NOTICE it sends
 * at registration.  The registry is a static table with no reset, so each
 * test uses addresses of its own.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <cmocka.h>

#include "config.h"
#include "IPcheck.h"
#include "client.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "numeric.h"
#include "res.h"

/* --- stubs ----------------------------------------------------------- */

/* Not test_stub.o: its debug() prints every Debug() line, and the overflow
 * test below makes 65535 remote connects. */
struct Client me;
int log_inassert;
time_t CurrentTime;

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
}

void debug(int level, const char *form, ...)
{
  (void)level; (void)form;
}

static int clone_limit = 4;
static int clone_period = 40;
static int clone_delay = 0;
static int count_refusals = 1;
static int refund_limit = 0;

int feature_int(enum Feature feat)
{
  switch (feat) {
  case FEAT_IPCHECK_CLONE_LIMIT: return clone_limit;
  case FEAT_IPCHECK_CLONE_PERIOD: return clone_period;
  case FEAT_IPCHECK_CLONE_DELAY: return clone_delay;
  case FEAT_IPCHECK_SASL_REFUND: return refund_limit;
  case FEAT_IPCHECK_SASL_REFUND_PERIOD: return 600;
  default: return 0;           /* IPCHECK_SASL_REFUND off, and the rest */
  }
}

int feature_bool(enum Feature feat)
{
  if (feat == FEAT_IPCHECK_COUNT_REFUSALS)
    return count_refusals;
  return 0;
}

struct Timer* timer_init(struct Timer* timer) { return timer; }
void timer_add(struct Timer* timer, EventCallBack call, void* data,
               enum TimerType type, time_t value)
{
  (void)timer; (void)call; (void)data; (void)type; (void)value;
}

/* The registration NOTICE: "%C :on %u ca %u(%u) ft %u(%u)%s". */
static int notices;
static unsigned int notice_on, notice_ca;

void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...)
{
  va_list vl;
  (void)from; (void)cmd; (void)tok; (void)to; (void)pattern;
  va_start(vl, pattern);
  (void)va_arg(vl, struct Client *);
  notice_on = va_arg(vl, unsigned int);
  notice_ca = va_arg(vl, unsigned int);
  va_end(vl);
  ++notices;
}

/* STATS ipcheck's lines: send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
 * pattern, ...), which uses only standard conversions. */
#define MAX_REPLIES 32
static char replies[MAX_REPLIES][512];
static int nreplies;

int send_reply(struct Client *to, int reply, ...)
{
  va_list vl;
  const char *pattern;
  (void)to;
  assert_true(reply & SND_EXPLICIT);
  assert_int_equal(reply & ~SND_EXPLICIT, RPL_STATSDEBUG);
  va_start(vl, reply);
  pattern = va_arg(vl, const char *);
  if (nreplies < MAX_REPLIES)
    vsnprintf(replies[nreplies++], sizeof(replies[0]), pattern, vl);
  va_end(vl);
  return 0;
}

/* --- helpers --------------------------------------------------------- */

static struct Connection me_con;

struct test_client {
  struct Client cli;
  struct Connection con;
};

static void make_test_client(struct test_client *tc, const char *ip)
{
  memset(tc, 0, sizeof(*tc));
  tc->cli.cli_connect = &tc->con;
  tc->con.con_client = &tc->cli;        /* MyConnect */
  if (ip)
    assert_true(ircd_aton(&tc->cli.cli_ip, ip) > 0);
}

static int setup(void **state)
{
  (void)state;
  clone_limit = 4;
  clone_period = 40;
  clone_delay = 0;
  count_refusals = 1;
  refund_limit = 0;
  notices = 0;
  nreplies = 0;
  me.cli_connect = &me_con;
  me_con.con_since = 1000;
  CurrentTime += 100000;        /* past the boot grace, and never back: an
                                 * earlier test's entries age, never un-age */
  return 0;
}

static int local_connect(const char *ip)
{
  struct irc_in_addr addr;
  time_t next = 0;
  assert_true(ircd_aton(&addr, ip) > 0);
  return IPcheck_local_connect(&addr, &next);
}

/* --- the local throttle (regression net) ------------------------------ */

/* The fourth connection inside the window is refused, the refusal leaves
 * the live count as it was, and a quiet gap starts the count over. */
static void test_local_throttle(void **state)
{
  struct test_client tc;
  (void)state;
  make_test_client(&tc, "192.0.2.1");

  assert_true(local_connect("192.0.2.1"));
  assert_true(local_connect("192.0.2.1"));
  assert_true(local_connect("192.0.2.1"));
  assert_int_equal(IPcheck_nr(&tc.cli), 3);
  assert_false(local_connect("192.0.2.1"));
  assert_int_equal(IPcheck_nr(&tc.cli), 3);

  CurrentTime += clone_period + 1;
  assert_true(local_connect("192.0.2.1"));
  assert_int_equal(IPcheck_nr(&tc.cli), 4);
}

/* A connection given back (rejected through no fault of its own) never
 * takes the attempt count below one. */
static void test_connect_fail_floor(void **state)
{
  struct test_client tc;
  (void)state;
  make_test_client(&tc, "192.0.2.2");
  assert_true(local_connect("192.0.2.2"));
  SetIPChecked(&tc.cli);
  IPcheck_connect_fail(&tc.cli, 1);
  assert_int_equal(IPcheck_nr(&tc.cli), 0);
  assert_true(local_connect("192.0.2.2"));
  IPcheck_connect_succeeded(&tc.cli);
  assert_int_equal(notices, 1);
  assert_int_equal(notice_ca, 2);    /* the given-back attempt left 1, not 0 */
}

/* --- the 16-bit clock -------------------------------------------------- */

/* An address active just before the 16-bit clock wraps is judged by its
 * real age afterwards.  CONNECTED_SINCE() used to subtract in int, so
 * after the wrap the age read negative -- "recent" -- until the clock came
 * round again: with refusals not counted (nothing moves last_connect) an
 * address one connection short of its limit was refused for hours, and
 * for good while its clients stayed connected; with them counted, it cost
 * one spurious refusal. */
static void wrap_chain(int refusals_counted, const char *ip)
{
  count_refusals = refusals_counted;
  /* forward to the next moment the 16-bit clock reads 65500 */
  CurrentTime += (65500 - (CurrentTime & 0xffff)) & 0xffff;
  assert_true(local_connect(ip));
  assert_true(local_connect(ip));
  assert_true(local_connect(ip));
  CurrentTime += clone_period + 60;         /* past the window, and the wrap */
  assert_true(local_connect(ip));
}

static void test_age_across_clock_wrap(void **state)
{
  (void)state;
  wrap_chain(0, "192.0.2.60");
  wrap_chain(1, "192.0.2.61");
}

/* --- the remote check ------------------------------------------------- */

/* A remote check that would overflow the 16-bit live count refuses the
 * client, leaves the count where it was and leaves the client uncounted
 * (its exit then releases nothing).  It used to leave the counter wrapped
 * to 0 with the client still marked counted, so the next disconnect from
 * that address tripped assert(entry->connected > 0). */
static void test_remote_overflow_keeps_count(void **state)
{
  struct test_client tc;
  unsigned int i;
  (void)state;
  make_test_client(&tc, "198.51.100.7");

  for (i = 0; i < 0xffff; ++i) {
    ClearIPChecked(&tc.cli);
    assert_true(IPcheck_remote_connect(&tc.cli, 0));
  }
  assert_int_equal(IPcheck_nr(&tc.cli), 0xffff);

  ClearIPChecked(&tc.cli);
  assert_false(IPcheck_remote_connect(&tc.cli, 0));
  assert_int_equal(IPcheck_nr(&tc.cli), 0xffff);
  assert_false(IsIPChecked(&tc.cli));

  /* and a counted client's disconnect from that address still balances */
  SetIPChecked(&tc.cli);
  IPcheck_disconnect(&tc.cli);
  assert_int_equal(IPcheck_nr(&tc.cli), 0xfffe);
}

/* --- an address with no registry entry -------------------------------- */

/* A spoofed :: (WEBIRC or IAuth) is "counted" without a registry entry:
 * registering must not assert on the missing entry, and there is nothing
 * to report in the NOTICE. */
static void test_invalid_address_registers(void **state)
{
  struct test_client tc;
  (void)state;
  make_test_client(&tc, "::");
  assert_false(irc_in_addr_valid(&tc.cli.cli_ip));

  assert_true(IPcheck_remote_connect(&tc.cli, 0));
  assert_true(IsIPChecked(&tc.cli));
  IPcheck_connect_succeeded(&tc.cli);
  assert_int_equal(notices, 0);
  IPcheck_disconnect(&tc.cli);
}

/* --- the read-out (STATS ipcheck) ------------------------------------ */

static void report(const char *param)
{
  struct Client to;
  memset(&to, 0, sizeof(to));
  nreplies = 0;
  IPcheck_report(&to, NULL, (char *)param);
}

/* An address's line: its /32, the live count, the attempts, the age, the
 * targets, and what the next connection would meet. */
static void test_report_entry(void **state)
{
  (void)state;
  assert_true(local_connect("192.0.2.50"));
  assert_true(local_connect("192.0.2.50"));
  CurrentTime += 5;
  report("192.0.2.50");
  assert_int_equal(nreplies, 1);
  assert_string_equal(replies[0],
    "I :192.0.2.50/32: on 2, attempts 2, last connect or drop 5 s ago, "
    "free targets 10/10 (none kept), next connection accepted");
}

/* An address one connection from its limit says so, and for how long. */
static void test_report_refusing(void **state)
{
  (void)state;
  assert_true(local_connect("192.0.2.51"));
  assert_true(local_connect("192.0.2.51"));
  assert_true(local_connect("192.0.2.51"));
  CurrentTime += 10;
  report("192.0.2.51");
  assert_int_equal(nreplies, 1);
  assert_non_null(strstr(replies[0], "on 3, attempts 3, last connect or drop 10 s ago"));
  assert_non_null(strstr(replies[0], "next connection refused for 31 s"));
}

/* The verdict is the check's own: whatever it says, the next connection
 * gets, at every step of a chain and across the window's end. */
static void test_verdict_matches_check(void **state)
{
  struct irc_in_addr addr;
  struct IPcheckInfo info;
  int step;
  (void)state;
  assert_true(ircd_aton(&addr, "192.0.2.52") > 0);
  for (step = 0; step < 8; ++step) {
    int predicted = IPcheck_lookup(&addr, &info) ? !info.would_refuse : 1;
    assert_int_equal(local_connect("192.0.2.52"), predicted);
    CurrentTime += (step == 4) ? clone_period + 1 : 3;
  }
}

static void test_report_unknown_and_garbage(void **state)
{
  (void)state;
  report("198.51.100.200");
  assert_int_equal(nreplies, 1);
  assert_string_equal(replies[0],
    "I :198.51.100.200/32: no entry, the next connection starts a new count");
  report("not-an-address");
  assert_string_equal(replies[0], "I :IPcheck: \"not-an-address\" is not an address");
  report("*");                   /* parses as ::, which no entry can hold */
  assert_string_equal(replies[0], "I :IPcheck: \"*\" is not an address");
  report("192.0.2.0/24");        /* a mask is not an address either */
  assert_string_equal(replies[0], "I :IPcheck: \"192.0.2.0/24\" is not an address");
  report("192.0.*");             /* ipmask_parse takes this as 192.0.0.0 */
  assert_string_equal(replies[0], "I :IPcheck: \"192.0.*\" is not an address");
  report("2001:db8:*");          /* and this as 2001:db8:: */
  assert_string_equal(replies[0], "I :IPcheck: \"2001:db8:*\" is not an address");
}

/* An IPv6 address shares its entry with its whole /64, and says so. */
static void test_report_ipv6_key(void **state)
{
  (void)state;
  assert_true(local_connect("2001:db8:1:2::5"));
  report("2001:db8:1:2:ffff::9");
  assert_int_equal(nreplies, 1);
  assert_non_null(strstr(replies[0], "I :2001:db8:1:2::/64: on 1, attempts 1"));
}

/* A real 6to4 client is keyed on the 48 bits that embed an IPv4 address,
 * like that address's own clients, and is shown as that /48, not as an
 * IPv4 address it is not. */
static void test_report_6to4_key(void **state)
{
  (void)state;
  assert_true(local_connect("2002:cb00:7107:9::1"));
  report("2002:cb00:7107:9::1");
  assert_int_equal(nreplies, 1);
  assert_non_null(strstr(replies[0], "I :2002:cb00:7107::/48: on 1, attempts 1"));
  report("2002:cb00:7107::");    /* its IPv4 form, 203.0.113.7, has its own key */
  assert_non_null(strstr(replies[0], "I :203.0.113.7/32: "));
}

/* Without an address: totals, the rule, the refund table, then the ten
 * busiest entries, most connections first -- ten of more than ten. */
static void test_report_summary(void **state)
{
  int i;
  unsigned int prev = 0xffffffff, on, entries;
  char ip[32];
  (void)state;
  for (i = 1; i <= 12; ++i) {
    snprintf(ip, sizeof(ip), "203.0.113.%d", 100 + i);
    assert_true(local_connect(ip));
  }
  report(NULL);
  assert_true(nreplies >= 4);
  assert_int_equal(sscanf(replies[0], "I :IPcheck: entries %u,", &entries), 1);
  assert_true(entries >= 12);
  assert_non_null(strstr(replies[0], ", connections counted "));
  assert_non_null(strstr(replies[1], "number 4 in a chain of gaps up to 40 s"));
  assert_non_null(strstr(replies[1], "refusals counted"));
  assert_string_equal(replies[2], "I :IPcheck: SASL refunds off (IPCHECK_SASL_REFUND 0)");
  assert_int_equal(nreplies - 3, 10);
  for (i = 3; i < nreplies; ++i) {
    const char *p = strstr(replies[i], ": on ");
    assert_non_null(p);
    assert_int_equal(sscanf(p, ": on %u,", &on), 1);
    assert_true(on <= prev);
    prev = on;
  }
}

/* The verdict at the limit's edges is the check's own: a limit of 1 or
 * less refuses every reconnect whatever the gap, and says so with no
 * countdown (it used to count down to a refusal that would not end); a
 * chain saturated at 255 meets a limit past that as the check meets it,
 * which differs between the two refusal policies. */
static void test_verdict_at_odd_limits(void **state)
{
  struct irc_in_addr addr;
  struct IPcheckInfo info;
  int i;
  (void)state;

  clone_limit = 1;
  assert_true(local_connect("192.0.2.54"));
  assert_true(ircd_aton(&addr, "192.0.2.54") > 0);
  assert_true(IPcheck_lookup(&addr, &info));     /* inside the window */
  assert_int_equal(info.would_refuse, IPCHECK_REFUSE_LIMIT);
  CurrentTime += clone_period + 20;
  assert_true(IPcheck_lookup(&addr, &info));     /* and after it */
  assert_int_equal(info.would_refuse, IPCHECK_REFUSE_LIMIT);
  assert_int_equal(info.retry_in, 0);
  report("192.0.2.54");
  assert_non_null(strstr(replies[0], "next connection refused at any gap (IPCHECK_CLONE_LIMIT 1)"));
  assert_false(local_connect("192.0.2.54"));    /* and the check agrees */

  clone_limit = 0;                               /* inside the window too */
  assert_true(local_connect("192.0.2.55"));      /* a new entry is always let in */
  assert_true(ircd_aton(&addr, "192.0.2.55") > 0);
  assert_true(IPcheck_lookup(&addr, &info));
  assert_int_equal(info.would_refuse, IPCHECK_REFUSE_LIMIT);
  assert_false(local_connect("192.0.2.55"));

  clone_limit = 1000;
  for (i = 0; i < 300; ++i)
    assert_true(local_connect("192.0.2.56"));
  assert_true(ircd_aton(&addr, "192.0.2.56") > 0);
  assert_true(IPcheck_lookup(&addr, &info));
  assert_int_equal(info.attempts, 255);
  clone_limit = 256;
  assert_true(IPcheck_lookup(&addr, &info));     /* counted: 255 stays under 256 */
  assert_int_equal(info.would_refuse, IPCHECK_REFUSE_NONE);
  assert_true(local_connect("192.0.2.56"));
  count_refusals = 0;                            /* not counted: 255 + 1 reaches it */
  assert_true(IPcheck_lookup(&addr, &info));
  assert_int_equal(info.would_refuse, IPCHECK_REFUSE_WINDOW);
  assert_false(local_connect("192.0.2.56"));
}

/* With refunds on, the summary says how full the refund table is. */
static void test_report_refunds_on(void **state)
{
  (void)state;
  refund_limit = 10;
  report(NULL);
  assert_true(nreplies >= 3);
  assert_non_null(strstr(replies[2], "I :IPcheck: SASL refunds 10 per account per 600 s; 0 of 4096 accounts hold a window"));
}

/* Whatever a ::-counted client does later finds no entry, the loopback's
 * least of all: `::` shares its upper 64 bits with `::1`, which is all the
 * registry matches an IPv6 key on.  IAuth re-keying it a second time, a
 * nick override, a SASL refund and Client{maxlinks} all look it up. */
static void test_invalid_address_touches_no_entry(void **state)
{
  struct test_client lo, sp;
  (void)state;
  make_test_client(&lo, "::1");
  make_test_client(&sp, "::");
  assert_true(local_connect("::1"));
  assert_true(local_connect("::1"));
  assert_true(local_connect("::1"));
  SetIPChecked(&lo.cli);

  assert_true(IPcheck_remote_connect(&sp.cli, 0));
  assert_int_equal(IPcheck_nr(&sp.cli), 0);
  IPcheck_connect_fail(&sp.cli, 1);
  refund_limit = 10;
  IPcheck_login_refund(&sp.cli, "alice");

  assert_int_equal(IPcheck_nr(&lo.cli), 3);
  IPcheck_connect_succeeded(&lo.cli);
  assert_int_equal(notice_on, 3);
  assert_int_equal(notice_ca, 3);
}

/* The harness itself: IPcheck.c's assert() reaches mock_assert(). */
static void test_asserts_are_observed(void **state)
{
  struct test_client tc;
  (void)state;
  make_test_client(&tc, "203.0.113.9");
  expect_assert_failure(IPcheck_connect_fail(&tc.cli, 0)); /* not IPChecked */
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(test_local_throttle, setup),
    cmocka_unit_test_setup(test_connect_fail_floor, setup),
    cmocka_unit_test_setup(test_age_across_clock_wrap, setup),
    cmocka_unit_test_setup(test_remote_overflow_keeps_count, setup),
    cmocka_unit_test_setup(test_invalid_address_registers, setup),
    cmocka_unit_test_setup(test_invalid_address_touches_no_entry, setup),
    cmocka_unit_test_setup(test_report_entry, setup),
    cmocka_unit_test_setup(test_report_refusing, setup),
    cmocka_unit_test_setup(test_verdict_matches_check, setup),
    cmocka_unit_test_setup(test_report_unknown_and_garbage, setup),
    cmocka_unit_test_setup(test_report_ipv6_key, setup),
    cmocka_unit_test_setup(test_report_6to4_key, setup),
    cmocka_unit_test_setup(test_report_summary, setup),
    cmocka_unit_test_setup(test_report_refunds_on, setup),
    cmocka_unit_test_setup(test_verdict_at_odd_limits, setup),
    cmocka_unit_test_setup(test_asserts_are_observed, setup),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
