/*
 * dnsbl_rehash_cmocka.c - a native DNSBL answer that arrives after a
 * REHASH is judged by the configuration in force then
 *
 * dnsbl_check() starts one DNS query per configured DNSBL entry; the
 * answers arrive a loop pass or more later (dnsbl_dns_callback()).  A
 * rehash in between frees every entry (dnsbl_clear_servers()) and parses
 * the new ones.  The query names its entry (domain, matched reply values),
 * and the answer is judged by the live entry of that name: gone or
 * changed, the answer is ignored.
 *
 * This includes the real dnsbl.c, compiled with -ffunction-sections and
 * linked with --gc-sections; the resolver (gethost_byname()) keeps the
 * queries for the case to answer, and auth_dnsbl_complete() counts.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "../dnsbl.c"

/* ------------------------------------------------------------------ */
/* The ircd around the DNSBL                                           */
/* ------------------------------------------------------------------ */

time_t CurrentTime;
int log_inassert;

void debug(int level, const char *form, ...) {}
void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...) {}
int feature_bool(enum Feature feat) { return 1; }      /* FEAT_NATIVE_DNSBL */
int feature_int(enum Feature feat) { return 3600; }    /* FEAT_DNSBL_CACHETIME */

/** The resolver: the queries made, for the case to answer. */
struct query {
  char name[256];
  dns_callback_f cb;
  void *ctx;
};
static struct query queries[8];
static int nqueries;
void gethost_byname(const char *name, dns_callback_f callback, void *ctx)
{
  assert_true(nqueries < 8);
  ircd_strncpy(queries[nqueries].name, name, sizeof(queries[nqueries].name));
  queries[nqueries].cb = callback;
  queries[nqueries].ctx = ctx;
  nqueries++;
}

/** Answer query \a i: listed (127.0.0.\a last) or not (NULL). */
static void answer(int i, int listed, int last)
{
  struct irc_in_addr addr;

  memset(&addr, 0, sizeof(addr));
  addr.in6_16[5] = 0xffff;
  addr.in6_16[6] = htons(0x7f00);
  addr.in6_16[7] = (unsigned short)last;   /* as dnsbl.c reads the last octet */
  queries[i].cb(queries[i].ctx, listed ? &addr : NULL, listed ? queries[i].name : NULL);
}

static int completes;
void auth_dnsbl_complete(struct AuthRequest *auth) { completes++; }

static struct Client client;
static struct Connection con;
static struct AuthRequest *const its_auth = (struct AuthRequest *) &con;  /* any non-NULL */

/** A configuration pass: the entries are replaced. */
static void rehash_to(const char *domain, enum DNSBLAction action, const char *mark)
{
  dnsbl_clear_servers();
  if (domain)
    dnsbl_add_server(domain, NULL, 0, action, mark, 0);
}

static int setup(void **state)
{
  int i;

  (void)state;
  for (i = 0; i < DNSBL_CACHE_SIZE; i++)
    dnsbl_cache[i] = NULL;                /* (the entries leak: a test) */
  dnsbl_clear_servers();
  nqueries = completes = 0;
  CurrentTime = 1000;
  memset(&client, 0, sizeof(client));
  memset(&con, 0, sizeof(con));
  cli_connect(&client) = &con;
  cli_auth(&client) = its_auth;
  cli_ip(&client).in6_16[5] = 0xffff;
  cli_ip(&client).in6_16[6] = htons(0xc000);
  cli_ip(&client).in6_16[7] = htons(0x024d);   /* 192.0.2.77 */
  return 0;
}

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

/** No rehash: the answer is judged by the entry (the baseline). */
static void answer_judged_by_its_entry(void **state)
{
  struct DNSBLRequest *req = NULL;

  rehash_to("bl.test", DNSBL_ACT_BLOCK_ALL, NULL);
  assert_int_equal(dnsbl_check(&client, &req), 1);
  assert_int_equal(nqueries, 1);
  answer(0, 1, 2);
  assert_int_equal(req->action, DNSBL_ACT_BLOCK_ALL);
  assert_int_equal(completes, 1);
  assert_int_equal(dnsbl_first_server()->hits, 1);
  dnsbl_cancel(req);
}

/** The rehash removed the entry: the answer is ignored (the lookup still
 * completes), and nothing reads or writes the freed entry. */
static void removed_entry_answer_ignored(void **state)
{
  struct DNSBLRequest *req = NULL;

  rehash_to("bl.test", DNSBL_ACT_BLOCK_ALL, NULL);
  dnsbl_check(&client, &req);
  rehash_to("other.test", DNSBL_ACT_BLOCK_ALL, NULL);
  answer(0, 1, 2);
  assert_int_equal(req->action, DNSBL_ACT_NONE);
  assert_int_equal(completes, 1);
  assert_int_equal(dnsbl_first_server()->hits, 0);
  dnsbl_cancel(req);
}

/** The rehash kept the entry (same name, same reply values) and changed its
 * action: the live action applies, and the live entry counts the hit. */
static void kept_entry_judges_by_its_live_action(void **state)
{
  struct DNSBLRequest *req = NULL;

  rehash_to("bl.test", DNSBL_ACT_BLOCK_ALL, NULL);
  dnsbl_check(&client, &req);
  rehash_to("bl.test", DNSBL_ACT_MARK, "listed");
  answer(0, 1, 2);
  assert_int_equal(req->action, DNSBL_ACT_MARK);
  assert_string_equal(req->mark, "listed");
  assert_int_equal(dnsbl_first_server()->hits, 1);
  dnsbl_cancel(req);
}

/** The rehash changed which reply values the entry matches: the answer was
 * asked for another entry, and is ignored. */
static void changed_index_answer_ignored(void **state)
{
  struct DNSBLRequest *req = NULL;

  dnsbl_clear_servers();
  dnsbl_add_server("bl.test", "2", 0, DNSBL_ACT_BLOCK_ALL, NULL, 0);
  dnsbl_check(&client, &req);
  dnsbl_clear_servers();
  dnsbl_add_server("bl.test", "3", 0, DNSBL_ACT_BLOCK_ALL, NULL, 0);
  answer(0, 1, 2);
  assert_int_equal(req->action, DNSBL_ACT_NONE);
  dnsbl_cancel(req);
}

/** The client left (its request cancelled) and the list was rehashed: the
 * answers free the request, nothing completes. */
static void cancelled_request_freed_by_last_answer(void **state)
{
  struct DNSBLRequest *req = NULL;

  rehash_to("bl.test", DNSBL_ACT_BLOCK_ALL, NULL);
  dnsbl_add_server("bl2.test", NULL, 0, DNSBL_ACT_BLOCK_ALL, NULL, 0);
  dnsbl_check(&client, &req);
  assert_int_equal(nqueries, 2);
  dnsbl_cancel(req);
  rehash_to(NULL, DNSBL_ACT_NONE, NULL);
  answer(0, 1, 2);
  answer(1, 0, 0);
  assert_int_equal(completes, 0);
}

/** Two entries for one domain whose indexes the parser drops (250 and
 * 251 are past the 0-31 reply values: both match every value) share
 * domain and bitmask; each query's answer is still judged by its own
 * entry -- and after a rehash that removes the first, the second's
 * answers go to the second. */
static void same_domain_entries_keep_their_own_answers(void **state)
{
  struct DNSBLRequest *req = NULL;

  dnsbl_clear_servers();
  dnsbl_add_server("bl.test", "250", 0, DNSBL_ACT_BLOCK_ALL, NULL, 0);
  dnsbl_add_server("bl.test", "251", 0, DNSBL_ACT_MARK, "listed", 0);
  /* the list: 251 (added last) first, then 250 */
  dnsbl_check(&client, &req);
  assert_int_equal(nqueries, 2);
  answer(0, 1, 2);                         /* the 251 entry: listed */
  answer(1, 0, 0);                         /* the 250 entry: not */
  assert_int_equal(req->action, DNSBL_ACT_MARK);
  dnsbl_cancel(req);

  req = NULL;
  nqueries = 0;
  memset(dnsbl_cache, 0, sizeof(dnsbl_cache));   /* (not served from it) */
  dnsbl_check(&client, &req);
  answer(0, 0, 0);                         /* 251: not */
  answer(1, 1, 2);                         /* 250: listed */
  assert_int_equal(req->action, DNSBL_ACT_BLOCK_ALL);
  dnsbl_cancel(req);

  req = NULL;
  nqueries = 0;
  memset(dnsbl_cache, 0, sizeof(dnsbl_cache));   /* (not served from it) */
  dnsbl_check(&client, &req);
  dnsbl_clear_servers();                   /* the rehash drops 250 */
  dnsbl_add_server("bl.test", "251", 0, DNSBL_ACT_MARK, "listed", 0);
  answer(1, 1, 2);                         /* 250's answer: ignored */
  assert_int_equal(req->action, DNSBL_ACT_NONE);
  answer(0, 1, 2);                         /* 251's: its own entry */
  assert_int_equal(req->action, DNSBL_ACT_MARK);
  assert_int_equal(dnsbl_first_server()->hits, 1);
  dnsbl_cancel(req);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(answer_judged_by_its_entry, setup),
    cmocka_unit_test_setup(removed_entry_answer_ignored, setup),
    cmocka_unit_test_setup(kept_entry_judges_by_its_live_action, setup),
    cmocka_unit_test_setup(changed_index_answer_ignored, setup),
    cmocka_unit_test_setup(cancelled_request_freed_by_last_answer, setup),
    cmocka_unit_test_setup(same_domain_entries_keep_their_own_answers, setup),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
