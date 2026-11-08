/* chathistory_merge_cmocka.c - CMocka tests for the federated page merge
 *
 * Links the REAL ircd/chathistory_merge.c (../chathistory_merge.o): the
 * merge a federated CHATHISTORY page runs over the requester's local rows
 * and the rows its peers sent (send_fed_response, the auto-replay leg and
 * federated SEARCH), and the duplicate test the context splice uses.
 *
 * Under test:
 *  - a duplicate dropped by the merge hands its client-only tags to the
 *    row kept in its place when that row has none (a row fetched from a
 *    peer carries the tags a local copy stored without; W5 Task 2), and
 *    never overwrites tags the kept row has;
 *  - the semantic duplicate rule (one message stored on two servers under
 *    different msgids);
 *  - the trim direction (keep_oldest);
 *  - same-millisecond rows from two legs in msgid order (re-review R10);
 *  - the ownership hand-off of heap content to the copy (2026-09-06: two
 *    owners of one raw_content/dyn_content was a double free);
 *  - hm_trim_around: a merged AROUND page cut on its reference as a local
 *    AROUND page is (W5 Push D: keeping the newest rows drifted it off);
 *  - hm_context_parent: the row a peer's reaction or REDACT hangs on.
 *
 * The rows are built here; history_free_messages (history.c, which needs
 * the store) is defined here with the same body.
 */

#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <cmocka.h>

#include "history.h"
#include "chathistory_merge.h"
#include "ircd_alloc.h"
#include "ircd_string.h"

/* history.c's, verbatim: the merge frees the rows it trims with it. */
void history_free_messages(struct HistoryMessage *list)
{
  struct HistoryMessage *msg, *next;

  for (msg = list; msg; msg = next) {
    next = msg->next;
    if (msg->dyn_content)
      MyFree(msg->dyn_content);
    if (msg->raw_content)
      MyFree(msg->raw_content);
    MyFree(msg);
  }
}

/** One stored row: sender n!u@h, type 0 (PRIVMSG), content "x". */
static struct HistoryMessage *row(const char *msgid, const char *ts, const char *tags)
{
  struct HistoryMessage *m = (struct HistoryMessage *)MyCalloc(1, sizeof(*m));

  ircd_strncpy(m->msgid, msgid, sizeof(m->msgid));
  ircd_strncpy(m->timestamp, ts, sizeof(m->timestamp));
  ircd_strncpy(m->target, "#t", sizeof(m->target));
  ircd_strncpy(m->sender, "n!u@h", sizeof(m->sender));
  m->type = HISTORY_PRIVMSG;
  ircd_strncpy(m->content, "x", sizeof(m->content));
  ircd_strncpy(m->client_tags, tags, sizeof(m->client_tags));
  return m;
}

/** Link @a n rows into a list, in argument order. */
static struct HistoryMessage *chain(int n, ...)
{
  struct HistoryMessage *head = NULL, *tail = NULL;
  va_list ap;
  int i;

  va_start(ap, n);
  for (i = 0; i < n; i++) {
    struct HistoryMessage *m = va_arg(ap, struct HistoryMessage *);
    if (tail)
      tail->next = m;
    else
      head = m;
    tail = m;
  }
  va_end(ap);
  return head;
}

static int count(const struct HistoryMessage *m)
{
  int n = 0;
  for (; m; m = m->next)
    n++;
  return n;
}

/* The local copy has no tags (stored before relays kept them); the peer's
 * copy has +reply: the kept row takes the peer's. */
static void test_merge_adopts_tags_from_duplicate(void **s)
{
  struct HistoryMessage *a = row("AAAAAAAAAAAAA1", "1790000000.000", "");
  struct HistoryMessage *b = row("AAAAAAAAAAAAA1", "1790000000.000", "+reply=AAAAAAAAAAAAA0");
  struct HistoryMessage *m = hm_merge(a, b, 10, 0);

  (void)s;
  assert_non_null(m);
  assert_null(m->next);
  assert_string_equal(m->msgid, "AAAAAAAAAAAAA1");
  assert_string_equal(m->client_tags, "+reply=AAAAAAAAAAAAA0");
  history_free_messages(m);
  history_free_messages(a);
  history_free_messages(b);
}

/* Both copies have tags: the kept (local, first) row's stand. */
static void test_merge_keeps_first_tags(void **s)
{
  struct HistoryMessage *a = row("AAAAAAAAAAAAA1", "1790000000.000", "+reply=X");
  struct HistoryMessage *b = row("AAAAAAAAAAAAA1", "1790000000.000", "+reply=Y");
  struct HistoryMessage *m = hm_merge(a, b, 10, 0);

  (void)s;
  assert_non_null(m);
  assert_null(m->next);
  assert_string_equal(m->client_tags, "+reply=X");
  history_free_messages(m);
  history_free_messages(a);
  history_free_messages(b);
}

/* One message stored on two servers under two msgids: same time, sender,
 * type and content.  One row survives (the first in key order), and it
 * takes the duplicate's tags when it has none. */
static void test_merge_semantic_dup(void **s)
{
  struct HistoryMessage *a = row("AAAAAAAAAAAAA1", "1790000000.000", "");
  struct HistoryMessage *b = row("AAAAAAAAAAAAB1", "1790000000.000", "+reply=Z");
  struct HistoryMessage *m = hm_merge(a, b, 10, 0);

  (void)s;
  assert_non_null(m);
  assert_null(m->next);
  assert_string_equal(m->msgid, "AAAAAAAAAAAAA1");
  assert_string_equal(m->client_tags, "+reply=Z");
  assert_ptr_equal(hm_find_dup(m, b), m);
  history_free_messages(m);
  history_free_messages(a);
  history_free_messages(b);
}

/* Rows t1 < t2 < t3 from two legs, limit 2: a forward page keeps the
 * oldest two, a backward page the newest two. */
static void test_merge_trim_direction(void **s)
{
  struct HistoryMessage *a, *b, *m;

  (void)s;
  a = chain(2, row("AAAAAAAAAAAAA1", "1790000001.000", ""),
               row("AAAAAAAAAAAAA3", "1790000003.000", ""));
  b = chain(1, row("AAAAAAAAAAAAA2", "1790000002.000", ""));
  m = hm_merge(a, b, 2, 1);
  assert_int_equal(count(m), 2);
  assert_string_equal(m->timestamp, "1790000001.000");
  assert_string_equal(m->next->timestamp, "1790000002.000");
  history_free_messages(m);
  history_free_messages(a);
  history_free_messages(b);

  a = chain(2, row("AAAAAAAAAAAAA1", "1790000001.000", ""),
               row("AAAAAAAAAAAAA3", "1790000003.000", ""));
  b = chain(1, row("AAAAAAAAAAAAA2", "1790000002.000", ""));
  m = hm_merge(a, b, 2, 0);
  assert_int_equal(count(m), 2);
  assert_string_equal(m->timestamp, "1790000002.000");
  assert_string_equal(m->next->timestamp, "1790000003.000");
  history_free_messages(m);
  history_free_messages(a);
  history_free_messages(b);
}

/* Two different messages in one millisecond, B from the first leg and A
 * from the second: they come out A, B (store-key order). */
static void test_merge_same_ms_msgid_order(void **s)
{
  struct HistoryMessage *a = row("AAAAAAAAAAAAB1", "1790000000.000", "");
  struct HistoryMessage *b = row("AAAAAAAAAAAAA1", "1790000000.000", "");
  struct HistoryMessage *m;

  (void)s;
  ircd_strncpy(b->content, "y", sizeof(b->content));   /* not a semantic dup */
  m = hm_merge(a, b, 10, 0);
  assert_int_equal(count(m), 2);
  assert_string_equal(m->msgid, "AAAAAAAAAAAAA1");
  assert_string_equal(m->next->msgid, "AAAAAAAAAAAAB1");
  history_free_messages(m);
  history_free_messages(a);
  history_free_messages(b);
}

/* Heap content moves to the kept copy and leaves the source empty, so the
 * merged list and the source lists can each be freed (2026-09-06).  A
 * dropped duplicate keeps its own. */
static void test_merge_moves_heap_content(void **s)
{
  struct HistoryMessage *a = row("AAAAAAAAAAAAA1", "1790000001.000", "");
  struct HistoryMessage *b = chain(2, row("AAAAAAAAAAAAA1", "1790000001.000", ""),
                                      row("AAAAAAAAAAAAA2", "1790000002.000", ""));
  char *dyn = (char *)MyMalloc(8);
  unsigned char *raw = (unsigned char *)MyMalloc(8);
  char *dup_dyn = (char *)MyMalloc(8);
  struct HistoryMessage *m;

  (void)s;
  strcpy(dyn, "multi");
  a->dyn_content = dyn;
  a->dyn_content_len = 5;
  memcpy(raw, "zstd", 4);
  b->next->raw_content = raw;
  b->next->raw_content_len = 4;
  strcpy(dup_dyn, "multi");
  b->dyn_content = dup_dyn;          /* the duplicate's, dropped */
  b->dyn_content_len = 5;

  m = hm_merge(a, b, 10, 0);
  assert_int_equal(count(m), 2);
  assert_ptr_equal(m->dyn_content, dyn);
  assert_null(a->dyn_content);
  assert_int_equal(a->dyn_content_len, 0);
  assert_ptr_equal(m->next->raw_content, raw);
  assert_null(b->next->raw_content);
  assert_int_equal(b->next->raw_content_len, 0);
  assert_ptr_equal(b->dyn_content, dup_dyn);   /* not moved: freed with b */
  history_free_messages(m);
  history_free_messages(a);
  history_free_messages(b);
}

/* hm_find_dup: the matching row itself, or NULL. */
static void test_find_dup(void **s)
{
  struct HistoryMessage *list = chain(2, row("AAAAAAAAAAAAA1", "1790000001.000", ""),
                                         row("AAAAAAAAAAAAA2", "1790000002.000", ""));
  struct HistoryMessage *same = row("AAAAAAAAAAAAA2", "1790000009.000", "");
  struct HistoryMessage *other = row("AAAAAAAAAAAAA3", "1790000003.000", "");

  (void)s;
  assert_ptr_equal(hm_find_dup(list, same), list->next);
  assert_null(hm_find_dup(list, other));
  assert_null(hm_find_dup(NULL, other));
  history_free_messages(list);
  history_free_messages(same);
  history_free_messages(other);
}

/* The msgids of @a m, space-separated, for one assert_string_equal. */
static const char *ids(const struct HistoryMessage *m)
{
  static char buf[512];
  size_t n = 0;

  buf[0] = '\0';
  for (; m; m = m->next)
    n += (size_t)snprintf(buf + n, sizeof(buf) - n, "%s%s", n ? " " : "", m->msgid);
  return buf;
}

/* Seven rows a second apart, msgids P1 P2 P3 R Q1 Q2 Q3: the union a
 * federated AROUND page merges when the requester holds P2 P3 R Q1 and a
 * peer missing the P rows sent R Q1 Q2 Q3. */
static struct HistoryMessage *around_union(void)
{
  return chain(7, row("P1", "1790000001.000", ""), row("P2", "1790000002.000", ""),
                  row("P3", "1790000003.000", ""), row("R",  "1790000004.000", ""),
                  row("Q1", "1790000005.000", ""), row("Q2", "1790000006.000", ""),
                  row("Q3", "1790000007.000", ""));
}

/* AROUND msgid=R 4, as a local AROUND page is cut: the newest limit/2 rows
 * before the reference, then the reference and the rows after it up to the
 * limit.  (Keeping the newest four gave R Q1 Q2 Q3: off its reference.) */
static void test_trim_around_centres_on_msgid_ref(void **s)
{
  struct HistoryMessage *m;

  (void)s;
  m = hm_trim_around(around_union(), 4, 1790000004000ULL, "R");
  assert_string_equal(ids(m), "P2 P3 R Q1");
  history_free_messages(m);

  /* An odd limit: the after side takes the extra row. */
  m = hm_trim_around(around_union(), 5, 1790000004000ULL, "R");
  assert_string_equal(ids(m), "P2 P3 R Q1 Q2");
  history_free_messages(m);
}

/* Fewer rows before the reference than half the limit: the rows after it
 * fill the rest.  Fewer after: the before side is NOT topped up past
 * limit/2 -- a local AROUND page is not either. */
static void test_trim_around_short_sides(void **s)
{
  struct HistoryMessage *m;

  (void)s;
  m = hm_trim_around(around_union(), 4, 1790000002000ULL, "P2");
  assert_string_equal(ids(m), "P1 P2 P3 R");
  m = hm_trim_around(m, 4, 1790000006000ULL, "Q2");   /* before: P1 P2 P3 R */
  assert_string_equal(ids(m), "P3 R");
  history_free_messages(m);
}

/* A timestamp reference: the rows in its own millisecond belong to the
 * after side (a local AROUND anchors its after-walk one ms earlier); a
 * msgid reference splits that millisecond at the reference row, in msgid
 * order. */
static void test_trim_around_same_ms(void **s)
{
  struct HistoryMessage *m;

  (void)s;
  m = chain(4, row("A", "1790000003.000", ""), row("M3", "1790000004.000", ""),
               row("M5", "1790000004.000", ""), row("M7", "1790000005.000", ""));
  m = hm_trim_around(m, 2, 1790000004000ULL, NULL);
  assert_string_equal(ids(m), "A M3");
  history_free_messages(m);

  m = chain(4, row("A", "1790000003.000", ""), row("M3", "1790000004.000", ""),
               row("M5", "1790000004.000", ""), row("M7", "1790000004.000", ""));
  m = hm_trim_around(m, 2, 1790000004000ULL, "M5");
  assert_string_equal(ids(m), "M3 M5");
  history_free_messages(m);
}

/* Nothing to cut under the limit; an empty list stays empty. */
static void test_trim_around_under_limit(void **s)
{
  struct HistoryMessage *m;

  (void)s;
  m = hm_trim_around(around_union(), 10, 1790000004000ULL, "R");
  assert_int_equal(count(m), 7);
  history_free_messages(m);
  assert_null(hm_trim_around(NULL, 4, 1790000004000ULL, "R"));
}

/* The row a reaction or REDACT hangs on, by the reply index's own rule
 * (history.c: a TAGMSG's +reply, else +draft/reply; a REDACT's first
 * content word); anything else hangs on nothing. */
static void test_context_parent(void **s)
{
  char buf[HISTORY_MSGID_LEN];
  struct HistoryMessage *m = row("C", "1790000004.000", "+draft/react=x;+reply=PARENT");

  (void)s;
  m->type = HISTORY_TAGMSG;
  assert_string_equal(hm_context_parent(m, buf, sizeof buf), "PARENT");
  ircd_strncpy(m->client_tags, "+draft/reply=OLD;+draft/react=x", sizeof(m->client_tags));
  assert_string_equal(hm_context_parent(m, buf, sizeof buf), "OLD");
  ircd_strncpy(m->client_tags, "+draft/reply=OLD;+reply=NEW", sizeof(m->client_tags));
  assert_string_equal(hm_context_parent(m, buf, sizeof buf), "NEW");
  ircd_strncpy(m->client_tags, "+xreply=NO;+draft/react=x", sizeof(m->client_tags));
  assert_null(hm_context_parent(m, buf, sizeof buf));

  m->type = HISTORY_REDACT;
  ircd_strncpy(m->client_tags, "", sizeof(m->client_tags));
  ircd_strncpy(m->content, "TARGET :spam", sizeof(m->content));
  assert_string_equal(hm_context_parent(m, buf, sizeof buf), "TARGET");
  ircd_strncpy(m->content, "TARGET", sizeof(m->content));
  assert_string_equal(hm_context_parent(m, buf, sizeof buf), "TARGET");

  /* A reply is a message in its own right, never context. */
  m->type = HISTORY_PRIVMSG;
  ircd_strncpy(m->client_tags, "+reply=PARENT", sizeof(m->client_tags));
  assert_null(hm_context_parent(m, buf, sizeof buf));
  history_free_messages(m);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_merge_adopts_tags_from_duplicate),
    cmocka_unit_test(test_merge_keeps_first_tags),
    cmocka_unit_test(test_merge_semantic_dup),
    cmocka_unit_test(test_merge_trim_direction),
    cmocka_unit_test(test_merge_same_ms_msgid_order),
    cmocka_unit_test(test_merge_moves_heap_content),
    cmocka_unit_test(test_find_dup),
    cmocka_unit_test(test_trim_around_centres_on_msgid_ref),
    cmocka_unit_test(test_trim_around_short_sides),
    cmocka_unit_test(test_trim_around_same_ms),
    cmocka_unit_test(test_trim_around_under_limit),
    cmocka_unit_test(test_context_parent),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
