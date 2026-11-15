/*
 * dnsbl_cmocka.c - the native DNSBL, modelled on the iauthd scripts
 *
 * An answer is an address 127.0.0.<n>; <n>, its LAST octet, is the reply
 * value, read from the address bytes whatever the host's byte order.  An
 * entry with an index matches when the value equals one of the listed
 * values (any of 0-255); with a bitmask when value & bitmask is not zero;
 * with neither, any answer matches (tools/iauthd-ts/src/dnsbl.ts
 * matchesDNSBL()).  An index that is not a list of 0-255 values is a
 * configuration error.
 *
 * dnsbl_check() starts one DNS query per configured DNSBL entry; the
 * answers arrive a loop pass or more later (dnsbl_dns_callback()).  A
 * rehash in between frees every entry (dnsbl_clear_servers()) and parses
 * the new ones.  The query names its entry, and the answer is judged by
 * the live entry of that name: gone or changed, the answer is ignored.
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

/** What the resolver says a call without an address means (a server's
 * NXDOMAIN unless a case says the lookup failed). */
static enum ResOutcome outcome = RES_OUT_NXDOMAIN;
enum ResOutcome res_last_outcome(void) { return outcome; }

/** Query \a i failed: a timeout (or SERVFAIL) -- no address, no answer. */
static void answer_failed(int i)
{
  outcome = RES_OUT_FAILURE;
  queries[i].cb(queries[i].ctx, NULL, NULL);
  outcome = RES_OUT_NXDOMAIN;
}

/** Answer query \a i: listed (127.0.\a third.\a last) or not (NULL).  The
 * address as the resolver hands it over: IPv4-mapped, network byte order. */
static void answer_addr(int i, int listed, int third, int last)
{
  struct irc_in_addr addr;
  unsigned char *b = (unsigned char *) &addr;

  memset(&addr, 0, sizeof(addr));
  b[10] = b[11] = 0xff;
  b[12] = 127;
  b[13] = 0;
  b[14] = (unsigned char) third;
  b[15] = (unsigned char) last;
  queries[i].cb(queries[i].ctx, listed ? &addr : NULL, listed ? queries[i].name : NULL);
}

static void answer(int i, int listed, int last)
{
  answer_addr(i, listed, 0, last);
}

/* s_conf.c: the marks given to the client. */
static char marks_given[8][32];
static int nmarks_given;
int add_mark(struct Client *sptr, const char *mark)
{
  assert_true(nmarks_given < 8);
  ircd_strncpy(marks_given[nmarks_given++], mark, sizeof(marks_given[0]));
  return 0;
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

/** Forget every cached result (the entries leak: a test). */
static void cache_reset(void)
{
  memset(dnsbl_cache, 0, sizeof(dnsbl_cache));
}

/** Start a lookup for the client (one must start), unanswered. */
static struct DNSBLRequest *lookup_started(void)
{
  struct DNSBLRequest *req = NULL;

  assert_int_equal(dnsbl_check(&client, &req), 1);
  return req;
}

static int setup(void **state)
{
  (void)state;
  cache_reset();
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

/** Two entries for one domain (index 250 and 251) each judge their own
 * query's answer -- and after a rehash that removes the first, the
 * second's answers still go to the second. */
static void same_domain_entries_keep_their_own_answers(void **state)
{
  struct DNSBLRequest *req = NULL;

  dnsbl_clear_servers();
  dnsbl_add_server("bl.test", "250", 0, DNSBL_ACT_BLOCK_ALL, NULL, 0);
  dnsbl_add_server("bl.test", "251", 0, DNSBL_ACT_MARK, "listed", 0);
  /* the list: 251 (added last) first, then 250 */
  dnsbl_check(&client, &req);
  assert_int_equal(nqueries, 2);
  answer(0, 1, 251);                       /* the 251 entry: listed */
  answer(1, 0, 0);                         /* the 250 entry: not */
  assert_int_equal(req->action, DNSBL_ACT_MARK);
  dnsbl_cancel(req);

  req = NULL;
  nqueries = 0;
  memset(dnsbl_cache, 0, sizeof(dnsbl_cache));   /* (not served from it) */
  dnsbl_check(&client, &req);
  answer(0, 0, 0);                         /* 251: not */
  answer(1, 1, 250);                       /* 250: listed */
  assert_int_equal(req->action, DNSBL_ACT_BLOCK_ALL);
  dnsbl_cancel(req);

  req = NULL;
  nqueries = 0;
  memset(dnsbl_cache, 0, sizeof(dnsbl_cache));   /* (not served from it) */
  dnsbl_check(&client, &req);
  dnsbl_clear_servers();                   /* the rehash drops 250 */
  dnsbl_add_server("bl.test", "251", 0, DNSBL_ACT_MARK, "listed", 0);
  answer(1, 1, 250);                       /* 250's answer: ignored */
  assert_int_equal(req->action, DNSBL_ACT_NONE);
  answer(0, 1, 251);                       /* 251's: its own entry */
  assert_int_equal(req->action, DNSBL_ACT_MARK);
  assert_int_equal(dnsbl_first_server()->hits, 1);
  dnsbl_cancel(req);
}

/** The model table: which answers each entry matches, as iauthd-ts's
 * matchesDNSBL() decides for the same configuration (tools/iauthd-ts). */
static void reply_values_match_as_the_scripts_do(void **state)
{
  static const struct { int third, last; } ans[] = {
    { 0, 2 }, { 0, 4 }, { 0, 100 }, { 0, 250 }, { 0, 251 }, { 0, 255 }, { 1, 2 }
  };
  static const struct { const char *index; unsigned int bitmask;
                        const char *want; } entries[] = {
    { "2",               0, "Y.....Y" },
    { "2,3,4,5,6,7,9",   0, "YY....Y" },
    { "250",             0, "...Y..." },
    { "251",             0, "....Y.." },
    { NULL,              4, ".YY..Y." },
    { NULL,              0, "YYYYYYY" },
  };
  size_t e, a;

  for (e = 0; e < sizeof(entries) / sizeof(entries[0]); e++)
    for (a = 0; a < sizeof(ans) / sizeof(ans[0]); a++) {
      struct DNSBLRequest *req = NULL;

      memset(dnsbl_cache, 0, sizeof(dnsbl_cache));
      dnsbl_clear_servers();
      assert_non_null(dnsbl_add_server("bl.test", entries[e].index,
                                       entries[e].bitmask,
                                       DNSBL_ACT_BLOCK_ALL, NULL, 0));
      nqueries = 0;
      assert_int_equal(dnsbl_check(&client, &req), 1);
      answer_addr(0, 1, ans[a].third, ans[a].last);
      if ((entries[e].want[a] == 'Y') != (req->action == DNSBL_ACT_BLOCK_ALL))
        fail_msg("index %s bitmask %u, answer 127.0.%d.%d: %s",
                 entries[e].index ? entries[e].index : "-", entries[e].bitmask,
                 ans[a].third, ans[a].last,
                 entries[e].want[a] == 'Y' ? "not matched" : "matched");
      dnsbl_cancel(req);
    }
}

/** An index that is not a comma-separated list of 0-255 values is
 * refused (the configuration error is reported by the parser), never
 * taken as match-all. */
static void junk_index_refused(void **state)
{
  static const char *junk[] = { "abc", "300", "2,x", ",", "-1", "2,,3x" };
  size_t i;

  for (i = 0; i < sizeof(junk) / sizeof(junk[0]); i++)
    if (dnsbl_add_server("bl.test", junk[i], 0, DNSBL_ACT_BLOCK_ALL, NULL, 0))
      fail_msg("index \"%s\" accepted", junk[i]);
  assert_null(dnsbl_first_server());
  assert_non_null(dnsbl_add_server("bl.test", " 2, 3 ,255", 0,
                                   DNSBL_ACT_BLOCK_ALL, NULL, 0));
}

/* ------------------------------------------------------------------ */
/* The cache: a second connection from the address within CACHETIME   */
/* ------------------------------------------------------------------ */

/** Look the client up and answer every query: listed (127.0.0.2) or
 * not.  Returns the request, completed. */
static struct DNSBLRequest *lookup(int listed)
{
  struct DNSBLRequest *req = NULL;
  int i, first = nqueries;

  assert_int_equal(dnsbl_check(&client, &req), 1);
  for (i = first; i < nqueries; i++)
    answer(i, listed, 2);
  return req;
}

/** The verdict a second connection gets: from the cache (no query) when
 * \a from_cache, else NULL after checking a lookup was started. */
static struct DNSBLRequest *again(int from_cache)
{
  struct DNSBLRequest *req = NULL;
  int before = nqueries;
  int started = dnsbl_check(&client, &req);

  if (from_cache) {
    assert_int_equal(started, 0);
    assert_int_equal(nqueries, before);
    assert_non_null(req);               /* a verdict to act on */
    assert_int_equal(req->pending_count, 0);
  } else {
    assert_int_equal(started, 1);
    assert_true(nqueries > before);
  }
  return req;
}

/** Found listed (block): a second connection within the cache time is
 * blocked too, without a lookup. */
static void cached_listing_blocks_again(void **state)
{
  struct DNSBLRequest *req;
  enum DNSBLAction action;
  const char *mark;

  rehash_to("bl.test", DNSBL_ACT_BLOCK_ALL, NULL);
  dnsbl_cancel(lookup(1));
  req = again(1);
  assert_int_equal(dnsbl_result(&client, req, &action, &mark), 1);
  assert_int_equal(action, DNSBL_ACT_BLOCK_ALL);
  dnsbl_cancel(req);
}

/** Found not listed (a server's NXDOMAIN): a second connection is let in
 * from the cache, without a lookup. */
static void cached_clean_lets_in(void **state)
{
  struct DNSBLRequest *req;
  enum DNSBLAction action;
  const char *mark;

  rehash_to("bl.test", DNSBL_ACT_BLOCK_ALL, NULL);
  dnsbl_cancel(lookup(0));
  req = again(1);
  assert_int_equal(dnsbl_result(&client, req, &action, &mark), 0);
  assert_int_equal(action, DNSBL_ACT_NONE);
  dnsbl_cancel(req);
}

/** A rehash kept the entry and changed its action: the cached answer is
 * judged by the live action (mark, with the live mark). */
static void cached_listing_judged_by_live_action(void **state)
{
  struct DNSBLRequest *req;
  enum DNSBLAction action;
  const char *mark;

  rehash_to("bl.test", DNSBL_ACT_BLOCK_ALL, NULL);
  dnsbl_cancel(lookup(1));
  rehash_to("bl.test", DNSBL_ACT_MARK, "listed");
  req = again(1);
  assert_int_equal(dnsbl_result(&client, req, &action, &mark), 0);
  assert_int_equal(action, DNSBL_ACT_MARK);
  assert_string_equal(mark, "listed");
  dnsbl_cancel(req);
}

/** A rehash added an entry, or changed an entry's index: the cache has no
 * answer for it -- stale, looked up again (and the fresh answers cached). */
static void rehash_adding_or_changing_an_entry_makes_it_stale(void **state)
{
  struct DNSBLRequest *req;

  rehash_to("bl.test", DNSBL_ACT_BLOCK_ALL, NULL);
  dnsbl_cancel(lookup(0));
  dnsbl_add_server("bl2.test", NULL, 0, DNSBL_ACT_BLOCK_ALL, NULL, 0);
  req = again(0);
  answer(nqueries - 2, 0, 0);
  answer(nqueries - 1, 1, 2);
  assert_int_equal(req->action, DNSBL_ACT_BLOCK_ALL);
  dnsbl_cancel(req);
  dnsbl_cancel(again(1));                  /* the fresh answers are cached */

  dnsbl_clear_servers();
  dnsbl_add_server("bl.test", "3", 0, DNSBL_ACT_BLOCK_ALL, NULL, 0);
  dnsbl_add_server("bl2.test", NULL, 0, DNSBL_ACT_BLOCK_ALL, NULL, 0);
  req = again(0);                          /* bl.test's index changed */
  dnsbl_cancel(req);
}

/** A rehash removed the entry that listed the address: its cached answer
 * no longer counts; the remaining entry's does. */
static void removed_entry_cached_answer_ignored(void **state)
{
  struct DNSBLRequest *req = NULL;

  rehash_to("bl.test", DNSBL_ACT_BLOCK_ALL, NULL);
  dnsbl_add_server("bl2.test", NULL, 0, DNSBL_ACT_BLOCK_ALL, NULL, 0);
  assert_int_equal(dnsbl_check(&client, &req), 1);
  answer(0, 1, 2);                         /* bl2.test (added last, first) */
  answer(1, 0, 0);                         /* bl.test */
  dnsbl_cancel(req);
  rehash_to("bl.test", DNSBL_ACT_BLOCK_ALL, NULL);
  req = again(1);
  assert_int_equal(req->action, DNSBL_ACT_NONE);
  dnsbl_cancel(req);
}

/** The cache key is the address the lookup ASKED about: a client whose
 * address changes during the lookup (an IAuth I line, a WEBIRC) leaves the
 * answer under the old one.  A listed gateway: its listing is not cached
 * for the client's address.  A clean gateway: "clean" is not cached for
 * the client's address either. */
static void cache_keyed_by_the_address_asked_about(void **state)
{
  struct DNSBLRequest *req = NULL;
  struct irc_in_addr gateway, real;
  int listed;

  rehash_to("bl.test", DNSBL_ACT_BLOCK_ALL, NULL);
  memcpy(&gateway, &cli_ip(&client), sizeof(gateway));        /* 192.0.2.77 */
  memcpy(&real, &gateway, sizeof(real));
  real.in6_16[7] = htons(0x0263);                             /* 192.0.2.99 */
  for (listed = 1; listed >= 0; listed--) {
    cache_reset();
    memcpy(&cli_ip(&client), &gateway, sizeof(gateway));
    req = lookup_started();
    memcpy(&cli_ip(&client), &real, sizeof(real));            /* I / WEBIRC */
    answer(nqueries - 1, listed, 2);
    dnsbl_cancel(req);
    dnsbl_cancel(again(0));                                   /* real: asked */
    memcpy(&cli_ip(&client), &gateway, sizeof(gateway));
    req = again(1);                                           /* gateway: cached */
    assert_int_equal(req->action, listed ? DNSBL_ACT_BLOCK_ALL : DNSBL_ACT_NONE);
    dnsbl_cancel(req);
  }
}

/** The lookup timed out (or failed): the client is judged as today -- not
 * listed there, let in -- but nothing is cached: the next connection asks
 * again. */
static void failed_lookup_not_cached(void **state)
{
  struct DNSBLRequest *req = NULL;

  rehash_to("bl.test", DNSBL_ACT_BLOCK_ALL, NULL);
  assert_int_equal(dnsbl_check(&client, &req), 1);
  answer_failed(0);
  assert_int_equal(req->pending_count, 0);
  assert_int_equal(req->action, DNSBL_ACT_NONE);
  assert_int_equal(completes, 1);
  dnsbl_cancel(req);
  dnsbl_cancel(again(0));
}

/** One entry listed the address, another's lookup failed: the verdict
 * stands (blocked), but the address is not cached -- asked again. */
static void one_failed_lookup_caches_nothing(void **state)
{
  struct DNSBLRequest *req = NULL;

  rehash_to("bl.test", DNSBL_ACT_BLOCK_ALL, NULL);
  dnsbl_add_server("bl2.test", NULL, 0, DNSBL_ACT_BLOCK_ALL, NULL, 0);
  assert_int_equal(dnsbl_check(&client, &req), 1);
  answer(0, 1, 2);
  answer_failed(1);
  assert_int_equal(req->action, DNSBL_ACT_BLOCK_ALL);
  dnsbl_cancel(req);
  dnsbl_cancel(again(0));
}

/** Every matching entry whose action is mark marks a client that stays --
 * both mark entries; the reason of a block_anon entry the client is not
 * refused by (logged in), or of a whitelist entry, is no mark; an entry
 * that does not match marks nothing. */
static void every_matching_mark_entry_marks(void **state)
{
  struct DNSBLRequest *req = NULL;
  enum DNSBLAction action;
  const char *mark;
  int i;

  dnsbl_clear_servers();
  dnsbl_add_server("uce.test", "2", 0, DNSBL_ACT_MARK, "uce-2", 0);
  dnsbl_add_server("cbl.test", "2", 0, DNSBL_ACT_MARK, "cbl", 0);
  dnsbl_add_server("sorbs.test", "2,3", 0, DNSBL_ACT_BLOCK_ANON, "sorbs", 0);
  dnsbl_add_server("tor.test", "4", 0, DNSBL_ACT_MARK, "tor", 0);
  assert_int_equal(dnsbl_check(&client, &req), 1);
  for (i = 0; i < nqueries; i++)
    answer(i, 1, 2);
  assert_int_equal(dnsbl_result(&client, req, &action, &mark), 1);
  assert_int_equal(action, DNSBL_ACT_BLOCK_ANON);
  nmarks_given = 0;
  dnsbl_apply_marks(&client, req);           /* logged in: it stays */
  assert_int_equal(nmarks_given, 2);
  for (i = 0; i < nmarks_given; i++)
    assert_true(!strcmp(marks_given[i], "uce-2") || !strcmp(marks_given[i], "cbl"));
  assert_true(IsMarked(&client));
  dnsbl_cancel(req);

  /* A whitelist entry's reason is no mark either. */
  req = NULL;
  nqueries = 0;
  cache_reset();
  ClrFlag(&client, FLAG_MARKED);
  dnsbl_clear_servers();
  dnsbl_add_server("wl.test", "2", 0, DNSBL_ACT_WHITELIST, "whitelist", 0);
  assert_int_equal(dnsbl_check(&client, &req), 1);
  answer(0, 1, 2);
  assert_int_equal(dnsbl_result(&client, req, &action, &mark), 0);
  assert_int_equal(action, DNSBL_ACT_WHITELIST);
  nmarks_given = 0;
  dnsbl_apply_marks(&client, req);
  assert_int_equal(nmarks_given, 0);
  assert_false(IsMarked(&client));
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
    cmocka_unit_test_setup(reply_values_match_as_the_scripts_do, setup),
    cmocka_unit_test_setup(junk_index_refused, setup),
    cmocka_unit_test_setup(every_matching_mark_entry_marks, setup),
    cmocka_unit_test_setup(cached_listing_blocks_again, setup),
    cmocka_unit_test_setup(cached_clean_lets_in, setup),
    cmocka_unit_test_setup(cached_listing_judged_by_live_action, setup),
    cmocka_unit_test_setup(rehash_adding_or_changing_an_entry_makes_it_stale, setup),
    cmocka_unit_test_setup(removed_entry_cached_answer_ignored, setup),
    cmocka_unit_test_setup(cache_keyed_by_the_address_asked_about, setup),
    cmocka_unit_test_setup(failed_lookup_not_cached, setup),
    cmocka_unit_test_setup(one_failed_lookup_caches_nothing, setup),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
