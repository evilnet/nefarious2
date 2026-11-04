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
#include <cmocka.h>

#include "config.h"
#include "IPcheck.h"
#include "client.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_string.h"
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
    cmocka_unit_test_setup(test_remote_overflow_keeps_count, setup),
    cmocka_unit_test_setup(test_invalid_address_registers, setup),
    cmocka_unit_test_setup(test_invalid_address_touches_no_entry, setup),
    cmocka_unit_test_setup(test_asserts_are_observed, setup),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
