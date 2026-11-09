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
 *  - hm_context_parent: the row a peer's reaction or REDACT hangs on;
 *  - the children request (W5 Task 14): hm_children_wanted (which of a
 *    page's rows to ask about, newest first with the monotone stop),
 *    hm_pack_ids / hm_parse_ids (a CH Q K line's msgid list), and
 *    hm_splice_context (the context splice, moved from m_chathistory.c);
 *  - the redaction filter of a history page (W5 Task 15): hm_redact_filter
 *    drops every message a REDACT of the page names, with no cap on their
 *    number (F-6), and its fail-closed form every message a REDACT could
 *    name.
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

/* ---- W5 Task 14: the children request's pure parts ---- */

static int received_calls;
static int received_always;      /* 0 or 1: a constant answer; -1: received_from */
static uint64_t received_from;   /* received(ms) = ms >= received_from */

/* A store's "was [ms, now] received here, clear of every absence?" */
static int fake_received(uint64_t ms, void *ctx)
{
  (void)ctx;
  received_calls++;
  if (received_always >= 0)
    return received_always;
  return ms >= received_from;
}

/* a(1000) b(2000) [context c(2500)] d(3000) e(4000), times in ms. */
static struct HistoryMessage *wanted_rows(void)
{
  struct HistoryMessage *m = chain(5, row("a", "1.000", ""), row("b", "2.000", ""),
                                      row("c", "2.500", ""), row("d", "3.000", ""),
                                      row("e", "4.000", ""));
  m->next->next->is_context = 1;
  return m;
}

/* received() rejects [b, now] and passes [d, now]: a and b are asked
 * about.  The oldest (a) is rejected and the newest (e) passes, so a
 * bisection finds the cut: a, e, b, d -- four calls for four rows. */
static void test_children_wanted_cuts_at_newest_unreceived(void **s)
{
  struct HistoryMessage *m = wanted_rows();
  const char *out[5] = { NULL, NULL, NULL, NULL, NULL };

  (void)s;
  received_calls = 0;
  received_always = -1;
  received_from = 3000;
  assert_int_equal(hm_children_wanted(m, fake_received, NULL, out, 5), 2);
  assert_string_equal(out[0], "a");
  assert_string_equal(out[1], "b");
  assert_null(out[2]);
  assert_int_equal(received_calls, 4);
  history_free_messages(m);
}

/* Every row's context range was received: nothing to ask.  The oldest
 * row passing settles it: one call. */
static void test_children_wanted_all_received(void **s)
{
  struct HistoryMessage *m = wanted_rows();
  const char *out[5] = { NULL, NULL, NULL, NULL, NULL };

  (void)s;
  received_calls = 0;
  received_always = 1;
  assert_int_equal(hm_children_wanted(m, fake_received, NULL, out, 5), 0);
  assert_null(out[0]);
  assert_int_equal(received_calls, 1);   /* the oldest row passes: so do the rest */
  history_free_messages(m);
}

/* None was: every non-context row, in time order; the context row c is no
 * parent (no context of context).  The oldest and the newest both reject:
 * two calls. */
static void test_children_wanted_none_received_skips_context(void **s)
{
  struct HistoryMessage *m = wanted_rows();
  const char *out[5] = { NULL, NULL, NULL, NULL, NULL };

  (void)s;
  received_calls = 0;
  received_always = 0;
  assert_int_equal(hm_children_wanted(m, fake_received, NULL, out, 5), 4);
  assert_string_equal(out[0], "a");
  assert_string_equal(out[1], "b");
  assert_string_equal(out[2], "d");
  assert_string_equal(out[3], "e");
  assert_null(out[4]);
  assert_int_equal(received_calls, 2);
  history_free_messages(m);
}

/* A full page (1000 rows, one a second): wherever the cut falls, the ids
 * are every row up to it and received() runs at most ceil(log2 n) + 2
 * times (fix round 1: the per-row check reads the window record and scans
 * every storage peer's absences). */
static void test_children_wanted_bisects(void **s)
{
  enum { N = 1000 };
  static const int cuts[] = { -1, 0, 1, 2, 499, 500, 997, 998, 999 };
  struct HistoryMessage *head = NULL, *tail = NULL, *m;
  static const char *out[N];
  char id[16], ts[24];
  size_t c;
  int i;

  (void)s;
  for (i = 0; i < N; i++) {
    snprintf(id, sizeof id, "R%04d", i);
    snprintf(ts, sizeof ts, "%d.000", i + 1);
    m = row(id, ts, "");
    if (tail)
      tail->next = m;
    else
      head = m;
    tail = m;
  }
  for (c = 0; c < sizeof(cuts) / sizeof(cuts[0]); c++) {
    int k = cuts[c];   /* rows 0..k rejected (-1: none) */
    received_calls = 0;
    received_always = -1;
    received_from = (uint64_t)(k + 2) * 1000ULL;   /* row i is at (i + 1) * 1000 ms */
    assert_int_equal(hm_children_wanted(head, fake_received, NULL, out, N), k + 1);
    if (k >= 0) {
      assert_string_equal(out[0], "R0000");
      snprintf(id, sizeof id, "R%04d", k);
      assert_string_equal(out[k], id);
    }
    assert_true(received_calls <= 12);   /* ceil(log2 1000) + 2 */
  }
  history_free_messages(head);
}

/* At most max ids are written, nothing past them. */
static void test_children_wanted_max(void **s)
{
  struct HistoryMessage *m = wanted_rows();
  const char *sentinel = "untouched";
  const char *out[4] = { NULL, NULL, sentinel, sentinel };

  (void)s;
  received_calls = 0;
  received_always = 0;
  assert_int_equal(hm_children_wanted(m, fake_received, NULL, out, 2), 2);
  assert_non_null(out[0]);
  assert_non_null(out[1]);
  assert_ptr_equal(out[2], sentinel);
  assert_ptr_equal(out[3], sentinel);
  assert_int_equal(hm_children_wanted(NULL, fake_received, NULL, out, 2), 0);
  history_free_messages(m);
}

/* Packing a CH Q K line's list: whole ids, space-separated, within room. */
static void test_pack_ids_room(void **s)
{
  const char *const in[3] = { "AAAAAAAAAAAAA1", "AAAAAAAAAAAAA2", "AAAAAAAAAAAAA3" };
  char out[64];

  (void)s;
  assert_int_equal(hm_pack_ids(in, 3, 0, 29, out, sizeof out), 2);
  assert_string_equal(out, "AAAAAAAAAAAAA1 AAAAAAAAAAAAA2");
  assert_int_equal(hm_pack_ids(in, 3, 0, 13, out, sizeof out), 0);
  assert_int_equal(hm_pack_ids(in, 3, 2, 14, out, sizeof out), 1);
  assert_string_equal(out, "AAAAAAAAAAAAA3");
  /* The output buffer bounds it too. */
  assert_int_equal(hm_pack_ids(in, 3, 0, 500, out, 20), 1);
  assert_string_equal(out, "AAAAAAAAAAAAA1");
  assert_int_equal(hm_pack_ids(in, 3, 3, 500, out, sizeof out), 0);
}

/* Parsing a CH Q K list in place: runs of spaces, an over-long token
 * skipped, at most max. */
static void test_parse_ids_tokens(void **s)
{
  char l1[] = "a  b c";
  char l2[128];
  char l3[] = "a b c";
  char l4[] = "  ";
  const char *out[4];
  int i;

  (void)s;
  assert_int_equal(hm_parse_ids(l1, out, 4), 3);
  assert_string_equal(out[0], "a");
  assert_string_equal(out[1], "b");
  assert_string_equal(out[2], "c");

  strcpy(l2, "x ");
  for (i = 0; i < 70; i++)
    strcat(l2, "L");
  strcat(l2, " y");
  assert_int_equal(hm_parse_ids(l2, out, 4), 2);
  assert_string_equal(out[0], "x");
  assert_string_equal(out[1], "y");

  assert_int_equal(hm_parse_ids(l3, out, 2), 2);
  assert_string_equal(out[0], "a");
  assert_string_equal(out[1], "b");

  assert_int_equal(hm_parse_ids(l4, out, 4), 0);
  assert_int_equal(hm_parse_ids(NULL, out, 4), 0);
}

/* A context row on @a parent. */
static struct HistoryMessage *ctx_row(const char *msgid, const char *ts, const char *parent)
{
  struct HistoryMessage *m = row(msgid, ts, "");

  m->type = HISTORY_TAGMSG;
  m->is_context = 1;
  ircd_strncpy(m->ctx_parent, parent, sizeof(m->ctx_parent));
  return m;
}

/* A spliced child goes after its parent's existing context run. */
static void test_splice_after_context_run(void **s)
{
  struct HistoryMessage *merged = chain(3, row("P", "1.000", ""), ctx_row("x", "2.000", "P"),
                                           row("Q", "3.000", ""));

  (void)s;
  hm_splice_context(merged, ctx_row("y", "2.500", "P"));
  assert_string_equal(ids(merged), "P x y Q");
  history_free_messages(merged);
}

/* Freed, merged unchanged: a duplicate of a child already there (by
 * msgid), a child whose parent is not on the page, and a child whose
 * parent is itself context (no context of context). */
static void test_splice_drops_dup_and_orphan(void **s)
{
  struct HistoryMessage *merged = chain(3, row("P", "1.000", ""), ctx_row("x", "2.000", "P"),
                                           row("Q", "3.000", ""));
  int before = count(merged);

  (void)s;
  hm_splice_context(merged, chain(3, ctx_row("x", "2.200", "P"),
                                     ctx_row("z", "2.300", "NOPE"),
                                     ctx_row("w", "2.400", "x")));
  assert_int_equal(count(merged), before);
  assert_string_equal(ids(merged), "P x Q");
  history_free_messages(merged);
}

/* ---- W5 Task 15: redaction and context on history pages ---- */

/* A row of @a type; a REDACT's content names @a target_msgid. */
static struct HistoryMessage *typed(const char *msgid, const char *ts, int type,
                                    const char *target_msgid)
{
  struct HistoryMessage *m = row(msgid, ts, "");

  m->type = type;
  if (type == HISTORY_REDACT)
    ircd_strncpy(m->content, target_msgid, sizeof(m->content));
  else if (type == HISTORY_TAGMSG)
    m->content[0] = '\0';
  return m;
}

/* A context row (history_attach_context's: is_context, no ctx_parent). */
static struct HistoryMessage *as_ctx(struct HistoryMessage *m)
{
  m->is_context = 1;
  return m;
}

/* F-6: no cap on the REDACT targets.  150 messages and their 150 REDACT
 * rows on one page (the old filter kept 100 targets and showed the rest):
 * every message goes, every REDACT stays.  Then the same with the REDACTs
 * as context, each after its message. */
static void test_redact_filter_no_cap(void **s)
{
  struct HistoryMessage *head = NULL, **tp = &head, *m;
  char id[16], ts[24], tgt[16];
  int i, n;

  (void)s;
  for (i = 0; i < 150; i++) {
    snprintf(id, sizeof id, "M%03d", i);
    snprintf(ts, sizeof ts, "1790000%03d.000", i);
    *tp = typed(id, ts, HISTORY_PRIVMSG, NULL);
    tp = &(*tp)->next;
  }
  for (i = 0; i < 150; i++) {
    snprintf(id, sizeof id, "D%03d", i);
    snprintf(ts, sizeof ts, "1790001%03d.000", i);
    snprintf(tgt, sizeof tgt, "M%03d", 149 - i);
    *tp = typed(id, ts, HISTORY_REDACT, tgt);
    tp = &(*tp)->next;
  }
  n = hm_redact_filter(&head, 300);
  assert_int_equal(n, 150);
  assert_int_equal(count(head), 150);
  for (m = head; m; m = m->next)
    assert_int_equal(m->type, HISTORY_REDACT);
  history_free_messages(head);

  head = NULL;
  tp = &head;
  for (i = 0; i < 150; i++) {
    snprintf(id, sizeof id, "M%03d", i);
    snprintf(ts, sizeof ts, "1790000%03d.000", i);
    *tp = typed(id, ts, HISTORY_PRIVMSG, NULL);
    tp = &(*tp)->next;
    snprintf(id, sizeof id, "D%03d", i);
    snprintf(tgt, sizeof tgt, "M%03d", i);
    *tp = as_ctx(typed(id, "1790009000.000", HISTORY_REDACT, tgt));
    tp = &(*tp)->next;
  }
  n = hm_redact_filter(&head, 150);
  assert_int_equal(n, 150);
  for (m = head; m; m = m->next)
    assert_int_equal(m->type, HISTORY_REDACT);
  history_free_messages(head);
}

/* Nothing dropped: the count comes back as given (here 7, not the list's
 * length). */
static void test_redact_filter_nothing_dropped(void **s)
{
  struct HistoryMessage *head = chain(3,
      typed("M", "1.000", HISTORY_PRIVMSG, NULL),
      typed("D", "5.000", HISTORY_REDACT, "X"),
      typed("N", "2.000", HISTORY_PRIVMSG, NULL));

  (void)s;
  assert_int_equal(hm_redact_filter(&head, 7), 7);
  assert_string_equal(ids(head), "M D N");
  history_free_messages(head);
  head = NULL;
  assert_int_equal(hm_redact_filter(&head, 0), 0);
  assert_int_equal(hm_redact_filter(NULL, 0), 0);
}

/* The fail-closed form (the target set could not be allocated): every row
 * a REDACT could name goes, context or not; REDACTs and events stay. */
static void test_redact_filter_closed(void **s)
{
  struct HistoryMessage *head = chain(6,
      typed("M", "1.000", HISTORY_PRIVMSG, NULL),
      as_ctx(typed("R", "5.000", HISTORY_TAGMSG, NULL)),
      typed("J", "2.000", HISTORY_JOIN, NULL),
      typed("D", "3.000", HISTORY_REDACT, "X"),
      typed("N", "4.000", HISTORY_NOTICE, NULL),
      typed("ML", "4.500", HISTORY_MULTILINE, NULL));

  (void)s;
  assert_int_equal(hm_redact_filter_closed(&head, 5), 2);
  assert_string_equal(ids(head), "J D");
  history_free_messages(head);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_redact_filter_no_cap),
    cmocka_unit_test(test_redact_filter_nothing_dropped),
    cmocka_unit_test(test_redact_filter_closed),
    cmocka_unit_test(test_children_wanted_cuts_at_newest_unreceived),
    cmocka_unit_test(test_children_wanted_all_received),
    cmocka_unit_test(test_children_wanted_none_received_skips_context),
    cmocka_unit_test(test_children_wanted_max),
    cmocka_unit_test(test_children_wanted_bisects),
    cmocka_unit_test(test_pack_ids_room),
    cmocka_unit_test(test_parse_ids_tokens),
    cmocka_unit_test(test_splice_after_context_run),
    cmocka_unit_test(test_splice_drops_dup_and_orphan),
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
