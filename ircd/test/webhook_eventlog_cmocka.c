/* cmocka suite for the applied-events log (include/webhook_eventlog.h):
 * the ring every server keeps of the Keycloak events it applied, keyed by
 * the event id, so a direct delivery, a relay or a catch-up line whose id
 * is already there is dropped instead of applied twice (webhook plan 4). */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <cmocka.h>

#include "../../include/webhook_eventlog.h"

#define T 1790300000L

static const char *UUID = "0b4a2f0e-1d4c-4c4a-9a1e-000000000001";

static void test_record_then_seen(void **s)
{
  (void)s;
  webhook_eventlog_init(8);
  assert_int_equal(webhook_eventlog_seen(UUID), 0);
  assert_int_equal(webhook_eventlog_record(UUID, 'D', "abc", "alice", T), 0);   /* recorded now */
  assert_int_equal(webhook_eventlog_seen(UUID), 1);
  assert_int_equal(webhook_eventlog_record(UUID, 'D', "abc", "alice", T + 1), 1); /* already there */
  assert_int_equal(webhook_eventlog_record("other-id", 'X', "", "", T), 0);
  assert_int_equal(webhook_eventlog_record(NULL, 'D', "abc", "alice", T), 0);     /* not stored */
  assert_int_equal(webhook_eventlog_record("", 'D', "abc", "alice", T), 0);
  assert_int_equal(webhook_eventlog_seen(NULL), 0);
  assert_int_equal(webhook_eventlog_seen(""), 0);
  assert_int_equal(webhook_eventlog_count(), 2);
}

/* Review focus 3: the log never grows past its capacity; the oldest goes. */
static void test_log_evicts_oldest_at_capacity(void **s)
{
  char id[16];
  int i;
  (void)s;
  webhook_eventlog_init(4);
  for (i = 0; i < 5; i++) {
    snprintf(id, sizeof(id), "e%d", i);
    assert_int_equal(webhook_eventlog_record(id, 'P', "", "", T + i), 0);
  }
  assert_int_equal(webhook_eventlog_count(), 4);
  assert_int_equal(webhook_eventlog_seen("e0"), 0);       /* evicted */
  for (i = 1; i < 5; i++) {
    snprintf(id, sizeof(id), "e%d", i);
    assert_int_equal(webhook_eventlog_seen(id), 1);
  }
  assert_true(webhook_eventlog_oldest() == T + 1);
}

struct seen_list { char ids[8][WH_EVENT_ID_LEN]; unsigned int n; };

static void collect(const struct WebhookEventLogEntry *e, void *data)
{
  struct seen_list *l = (struct seen_list *)data;
  if (l->n < 8)
    snprintf(l->ids[l->n], WH_EVENT_ID_LEN, "%s", e->id);
  l->n++;
}

/* Review focus 5: a catch-up sends the window's entries oldest first and
 * nothing older than the window. */
static void test_since_orders_oldest_first_and_stops_at_window(void **s)
{
  struct seen_list l;
  (void)s;
  webhook_eventlog_init(8);
  webhook_eventlog_record("e-new", 'D', "", "", T + 20);      /* recorded out of time order on purpose */
  webhook_eventlog_record("e-old", 'D', "", "", T);
  webhook_eventlog_record("e-mid", 'X', "", "", T + 10);
  memset(&l, 0, sizeof(l));
  assert_int_equal(webhook_eventlog_since(T + 5, collect, &l, 8), 2);
  assert_int_equal(l.n, 2);
  assert_string_equal(l.ids[0], "e-mid");
  assert_string_equal(l.ids[1], "e-new");
  memset(&l, 0, sizeof(l));
  assert_int_equal(webhook_eventlog_since(T + 21, collect, &l, 8), 0);
  memset(&l, 0, sizeof(l));
  assert_int_equal(webhook_eventlog_since(T, collect, &l, 8), 3);
  assert_string_equal(l.ids[0], "e-old");
}

static void test_since_honours_max(void **s)
{
  struct seen_list l;
  (void)s;
  webhook_eventlog_init(8);
  webhook_eventlog_record("a", 'D', "", "", T);
  webhook_eventlog_record("b", 'D', "", "", T + 1);
  webhook_eventlog_record("c", 'D', "", "", T + 2);
  memset(&l, 0, sizeof(l));
  assert_int_equal(webhook_eventlog_since(T, collect, &l, 2), 2);
  assert_string_equal(l.ids[0], "a");
  assert_string_equal(l.ids[1], "b");
}

/* Review focus 1: what may travel the wire as an event id or a kind. */
static void test_valid_id_and_kind(void **s)
{
  char longid[WH_EVENT_ID_LEN + 2];
  (void)s;
  assert_int_equal(webhook_eventlog_valid_id(UUID), 1);
  assert_int_equal(webhook_eventlog_valid_id("test-disable-1790300000"), 1);
  assert_int_equal(webhook_eventlog_valid_id("a.b:c_d-e"), 1);
  assert_int_equal(webhook_eventlog_valid_id(NULL), 0);
  assert_int_equal(webhook_eventlog_valid_id(""), 0);
  assert_int_equal(webhook_eventlog_valid_id("has space"), 0);
  assert_int_equal(webhook_eventlog_valid_id("ctl\x01"), 0);
  assert_int_equal(webhook_eventlog_valid_id("*"), 0);
  memset(longid, 'x', sizeof(longid) - 1);
  longid[sizeof(longid) - 1] = '\0';                      /* WH_EVENT_ID_LEN + 1 chars: too long */
  assert_int_equal(webhook_eventlog_valid_id(longid), 0);
  longid[WH_EVENT_ID_LEN - 1] = '\0';                     /* WH_EVENT_ID_LEN - 1 chars: the longest allowed */
  assert_int_equal(webhook_eventlog_valid_id(longid), 1);
  assert_int_equal(webhook_eventlog_valid_kind('D'), 1);
  assert_int_equal(webhook_eventlog_valid_kind('X'), 1);
  assert_int_equal(webhook_eventlog_valid_kind('R'), 1);
  assert_int_equal(webhook_eventlog_valid_kind('C'), 1);
  assert_int_equal(webhook_eventlog_valid_kind('E'), 1);
  assert_int_equal(webhook_eventlog_valid_kind('P'), 1);
  assert_int_equal(webhook_eventlog_valid_kind('Z'), 0);
  assert_int_equal(webhook_eventlog_valid_kind('\0'), 0);
  assert_int_equal(webhook_eventlog_valid_kind('d'), 0);
}

/* The entry keeps what a catch-up line needs: kind, Keycloak id, name. */
static void test_entry_carries_kind_id_and_name(void **s)
{
  struct seen_list l;
  (void)s;
  webhook_eventlog_init(2);
  webhook_eventlog_record(UUID, 'X', "kcid1", "alice", T);
  memset(&l, 0, sizeof(l));
  assert_int_equal(webhook_eventlog_since(T, collect, &l, 8), 1);
  assert_string_equal(l.ids[0], UUID);
}

/* Review focus 1: what a relay line must carry to be applied, and what is
 * refused without touching anything.  parv[0] is the command, as the ircd
 * parser hands it over. */
static void test_relay_parse_accepts_the_wire_forms(void **s)
{
  struct WebhookRelay r;
  char *five[] = { "CI", "alice", "kcid22", "0b4a2f0e-1d4c-4c4a-9a1e-000000000001", "D" };
  char *six[]  = { "CI", "*", "*", "evt-2", "X", "B" };
  (void)s;
  memset(&r, 0, sizeof(r));
  assert_int_equal(webhook_relay_parse(5, five, &r), 1);
  assert_string_equal(r.username, "alice");
  assert_string_equal(r.kc_id, "kcid22");
  assert_string_equal(r.event_id, "0b4a2f0e-1d4c-4c4a-9a1e-000000000001");
  assert_int_equal(r.kind, 'D');
  assert_int_equal(r.catchup, 0);
  memset(&r, 0, sizeof(r));
  assert_int_equal(webhook_relay_parse(6, six, &r), 1);
  assert_null(r.username);                 /* "*" = no name */
  assert_null(r.kc_id);                    /* "*" = no id */
  assert_string_equal(r.event_id, "evt-2");
  assert_int_equal(r.kind, 'X');
  assert_int_equal(r.catchup, 1);
}

static void test_relay_parse_rejects_junk(void **s)
{
  struct WebhookRelay r;
  char *four[]     = { "CI", "alice", "kcid22", "evt" };
  char *badkind[]  = { "CI", "alice", "kcid22", "evt", "Z" };
  char *badid[]    = { "CI", "alice", "kcid22", "has space", "D" };
  char *longid[]   = { "CI", "alice", "*", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "D" };
  char *badmark[]  = { "CI", "*", "*", "evt", "D", "Q" };
  char *emptyname[] = { "CI", "", "*", "evt", "D" };
  (void)s;
  assert_int_equal(webhook_relay_parse(4, four, &r), 0);
  assert_int_equal(webhook_relay_parse(5, badkind, &r), 0);
  assert_int_equal(webhook_relay_parse(5, badid, &r), 0);
  assert_int_equal(webhook_relay_parse(5, longid, &r), 0);
  assert_int_equal(webhook_relay_parse(6, badmark, &r), 0);
  assert_int_equal(webhook_relay_parse(5, emptyname, &r), 0);
  assert_int_equal(webhook_relay_parse(5, NULL, &r), 0);
  assert_int_equal(webhook_relay_parse(5, badkind, NULL), 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_relay_parse_accepts_the_wire_forms),
    cmocka_unit_test(test_relay_parse_rejects_junk),
    cmocka_unit_test(test_record_then_seen),
    cmocka_unit_test(test_log_evicts_oldest_at_capacity),
    cmocka_unit_test(test_since_orders_oldest_first_and_stops_at_window),
    cmocka_unit_test(test_since_honours_max),
    cmocka_unit_test(test_valid_id_and_kind),
    cmocka_unit_test(test_entry_carries_kind_id_and_name),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
