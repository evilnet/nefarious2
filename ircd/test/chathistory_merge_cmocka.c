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
 *    name; the context reactions of a message it drops go too, its REDACTs
 *    stay (F-7); a context reaction this store knows redacted, or cannot
 *    read, goes (F-2);
 *  - a federated page's context (W5 Task 15): hm_page_parent /
 *    hm_derive_context (a peer row with no CH C declaration whose own
 *    parent is on the page is context, F-3) and hm_fed_admit (context
 *    children have a budget apart from the rows', F-4);
 *  - fix round 1: the page leg's state (hm_page_leg: remove-on-match
 *    declarations, the derivation only once one was lost, the two budgets
 *    wired), a REDACT's target kept past every cap (hm_idset) and the
 *    fail-closed peer lists when even that overflows, F-7 for rows, and a
 *    row whose child could not be read;
 *  - fix round 2: a lost REDACT withholds the local rows too, a declared
 *    one lost keeps its target, every REDACT a peer sent is kept past the
 *    merge's cut, two responders declaring one child, and the CH B entries
 *    a request owns;
 *  - fix round 3: the responder's skip never drops a REDACT (and does no
 *    row skip on the children leg); the side set's duplicates.
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

/* The local-store check a page runs on a context row (F-2): an answer per
 * msgid prefix ("RED" redacted, "ERR" unreadable, else not), and a count. */
static int redacted_calls;
static int fake_redacted(const struct HistoryMessage *m, void *arg)
{
  (void)arg;
  redacted_calls++;
  if (strncmp(m->msgid, "RED", 3) == 0)
    return 1;
  if (strncmp(m->msgid, "ERR", 3) == 0)
    return -1;
  return 0;
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
  n = hm_redact_filter(&head, 300, NULL, NULL, NULL);
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
  n = hm_redact_filter(&head, 150, NULL, NULL, NULL);
  assert_int_equal(n, 150);
  for (m = head; m; m = m->next)
    assert_int_equal(m->type, HISTORY_REDACT);
  history_free_messages(head);
}

/* F-7: a message dropped for redaction takes its context reactions with
 * it, never its REDACT rows; another row's context stays.  A reaction
 * dropped that way is not looked up (F-2's check runs on survivors). */
static void test_redact_filter_drops_children_of_redacted(void **s)
{
  struct HistoryMessage *head = chain(6,
      typed("M", "1.000", HISTORY_PRIVMSG, NULL),
      as_ctx(typed("R", "5.000", HISTORY_TAGMSG, NULL)),
      as_ctx(typed("D", "6.000", HISTORY_REDACT, "M")),
      as_ctx(typed("R1", "7.000", HISTORY_TAGMSG, NULL)),
      typed("N", "2.000", HISTORY_PRIVMSG, NULL),
      as_ctx(typed("R2", "8.000", HISTORY_TAGMSG, NULL)));

  (void)s;
  redacted_calls = 0;
  assert_int_equal(hm_redact_filter(&head, 2, NULL, fake_redacted, NULL), 3);
  assert_string_equal(ids(head), "D N R2");
  assert_int_equal(redacted_calls, 1);
  history_free_messages(head);
}

/* F-2: each surviving context row that could be a target is checked once
 * against the local store: redacted or unreadable (fail closed) goes.  A
 * row, a REDACT row and a context reaction a REDACT of the list names are
 * not looked up. */
static void test_redact_filter_checks_context(void **s)
{
  struct HistoryMessage *head = chain(8,
      typed("M", "1.000", HISTORY_PRIVMSG, NULL),
      as_ctx(typed("REDa", "5.000", HISTORY_TAGMSG, NULL)),
      as_ctx(typed("ERRb", "6.000", HISTORY_TAGMSG, NULL)),
      as_ctx(typed("okc", "7.000", HISTORY_TAGMSG, NULL)),
      as_ctx(typed("okd", "7.500", HISTORY_TAGMSG, NULL)),
      as_ctx(typed("REDe", "8.000", HISTORY_REDACT, "okd")),
      typed("REDrow", "2.000", HISTORY_TAGMSG, NULL),
      typed("N", "3.000", HISTORY_PRIVMSG, NULL));

  (void)s;
  redacted_calls = 0;
  assert_int_equal(hm_redact_filter(&head, 3, NULL, fake_redacted, NULL), 5);
  assert_string_equal(ids(head), "M okc REDe REDrow N");
  assert_int_equal(redacted_calls, 3);   /* REDa, ERRb, okc */
  history_free_messages(head);
}

/* Nothing dropped: the count comes back as given (here 7, not the list's
 * length); no check without a callback (a server with no store has no
 * authority to ask).  With one, the redacted context row goes and the
 * count is the rows left. */
static void test_redact_filter_nothing_dropped(void **s)
{
  struct HistoryMessage *head = chain(3,
      typed("M", "1.000", HISTORY_PRIVMSG, NULL),
      as_ctx(typed("REDx", "5.000", HISTORY_TAGMSG, NULL)),
      typed("N", "2.000", HISTORY_PRIVMSG, NULL));

  (void)s;
  assert_int_equal(hm_redact_filter(&head, 7, NULL, NULL, NULL), 7);
  assert_string_equal(ids(head), "M REDx N");
  redacted_calls = 0;
  assert_int_equal(hm_redact_filter(&head, 7, NULL, fake_redacted, NULL), 2);
  assert_int_equal(redacted_calls, 1);
  assert_string_equal(ids(head), "M N");
  history_free_messages(head);
  head = NULL;
  assert_int_equal(hm_redact_filter(&head, 0, NULL, fake_redacted, NULL), 0);
  assert_int_equal(hm_redact_filter(NULL, 0, NULL, NULL, NULL), 0);
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

/* A reaction with +reply=@a parent. */
static struct HistoryMessage *reaction(const char *msgid, const char *ts, const char *parent)
{
  char tags[128];
  struct HistoryMessage *m;

  snprintf(tags, sizeof tags, "+draft/react=x;+reply=%s", parent);
  m = row(msgid, ts, tags);
  m->type = HISTORY_TAGMSG;
  m->content[0] = '\0';
  return m;
}

/* F-3: a page-leg row with no declaration is context when its own parent
 * is a row of the page: a local row, or a peer row that hangs on nothing
 * itself.  A child of a child, an orphan and a duplicate of a local row
 * stay rows (the merge decides them, as before). */
static void test_page_parent_derives_context(void **s)
{
  struct HistoryMessage *local = chain(2, row("P", "1.000", ""),
                                          reaction("dup", "1.500", "P"));
  struct HistoryMessage *peer = chain(7,
      reaction("rr", "6.000", "r1"),          /* child of a child: before it */
      row("A", "2.000", ""),
      reaction("r1", "3.000", "P"),           /* local parent */
      reaction("r2", "4.000", "A"),           /* peer parent */
      typed("rd", "5.000", HISTORY_REDACT, "A"),
      reaction("r3", "7.000", "GONE"),        /* parent not on the page */
      reaction("dup", "1.500", "P"));         /* the local row's copy */
  struct HistoryMessage *ctx = NULL;
  char buf[HISTORY_MSGID_LEN];

  (void)s;
  assert_string_equal(hm_page_parent(peer->next->next, local, peer, buf, sizeof buf), "P");
  assert_null(hm_page_parent(peer, local, peer, buf, sizeof buf));
  assert_null(hm_page_parent(peer->next, local, peer, buf, sizeof buf));
  assert_int_equal(hm_derive_context(&peer, local, &ctx), 3);
  assert_string_equal(ids(peer), "rr A r3 dup");
  assert_string_equal(ids(ctx), "r1 r2 rd");
  assert_int_equal(ctx->is_context, 1);
  assert_string_equal(ctx->ctx_parent, "P");
  assert_string_equal(ctx->next->ctx_parent, "A");
  assert_string_equal(ctx->next->next->ctx_parent, "A");
  /* Appended after what the list already held. */
  {
    struct HistoryMessage *more = chain(1, reaction("r4", "8.000", "A"));
    assert_int_equal(hm_derive_context(&more, NULL, &ctx), 0);   /* A is not local */
    assert_string_equal(ids(more), "r4");
    peer->next->next->next->next = more;   /* dup -> r4 */
    assert_int_equal(hm_derive_context(&peer, local, &ctx), 1);
    assert_string_equal(ids(ctx), "r1 r2 rd r4");
  }
  history_free_messages(local);
  history_free_messages(peer);
  history_free_messages(ctx);
}

/* F-4: a context child counts against its own cap, never the row cap, and
 * past it is dropped without touching the rows; a row past the row cap is
 * the cut (partial), as before. */
static void test_fed_admit_two_budgets(void **s)
{
  int rows = 0, ctx = 0, i;

  (void)s;
  assert_int_equal(hm_fed_admit(0, &rows, &ctx, 2, 3), HM_ADMIT_ROW);
  for (i = 0; i < 3; i++)
    assert_int_equal(hm_fed_admit(1, &rows, &ctx, 2, 3), HM_ADMIT_CONTEXT);
  assert_int_equal(hm_fed_admit(1, &rows, &ctx, 2, 3), HM_DROP_CONTEXT);
  assert_int_equal(rows, 1);
  assert_int_equal(ctx, 3);
  assert_int_equal(hm_fed_admit(0, &rows, &ctx, 2, 3), HM_ADMIT_ROW);
  assert_int_equal(hm_fed_admit(0, &rows, &ctx, 2, 3), HM_DROP_ROW);
  assert_int_equal(hm_fed_admit(1, &rows, &ctx, 2, 3), HM_DROP_CONTEXT);
  assert_int_equal(rows, 2);
  assert_int_equal(ctx, 3);
  /* 500 context children before a single row: the row still fits. */
  rows = ctx = 0;
  for (i = 0; i < 500; i++)
    hm_fed_admit(1, &rows, &ctx, 500, 500);
  assert_int_equal(hm_fed_admit(0, &rows, &ctx, 500, 500), HM_ADMIT_ROW);
}

/* ---- W5 Task 15 fix round 1 ---- */

/* A TAGMSG with no reply tag (a declared child carries its parent in the
 * declaration). */
static struct HistoryMessage *bare_tag(const char *msgid, const char *ts)
{
  return typed(msgid, ts, HISTORY_TAGMSG, NULL);
}

/* Remove-on-match: a responder sends each CH C right before its row, so
 * the 65th and later declarations are honoured exactly -- 70 children of
 * one row, each declared then sent, all context, the table never full.
 * The declaration's tags fill a child that brought none. */
static void test_leg_decl_remove_on_match(void **s)
{
  struct hm_page_leg leg;
  char id[16];
  int i;

  (void)s;
  memset(&leg, 0, sizeof(leg));
  assert_int_equal(hm_leg_add(&leg, row("P", "1.000", ""), NULL, 500, 500), HM_ADMIT_ROW);
  for (i = 0; i < 70; i++) {
    snprintf(id, sizeof id, "c%02d", i);
    hm_leg_declare(&leg, "P", id, "+draft/react=x;+reply=P", 500);
    assert_int_equal(leg.ndecl, 1);
    assert_int_equal(hm_leg_add(&leg, bare_tag(id, "9.000"), NULL, 500, 500), HM_ADMIT_CONTEXT);
    assert_int_equal(leg.ndecl, 0);
  }
  assert_int_equal(leg.decl_lost, 0);
  assert_int_equal(leg.rows, 1);
  assert_int_equal(leg.ctx, 70);
  assert_string_equal(leg.msgs->next->ctx_parent, "P");
  assert_string_equal(leg.msgs->next->client_tags, "+draft/react=x;+reply=P");
  hm_leg_free(&leg);
  assert_null(leg.msgs);
}

/* The derivation is a fallback: a peer's in-span reaction (never declared)
 * stays a row, as on a local page -- until a declaration is lost to a full
 * table; then an undeclared reaction whose parent is on the page is
 * context, at arrival and at completion.  Not on a request that is not a
 * page (derive 0). */
static void test_leg_fallback_flag(void **s)
{
  struct hm_page_leg leg;
  struct HistoryMessage *ctx = NULL, *late;
  char id[16];
  int i;

  (void)s;
  memset(&leg, 0, sizeof(leg));
  leg.derive = 1;
  hm_leg_add(&leg, row("A", "1.000", ""), NULL, 500, 500);
  assert_int_equal(hm_leg_add(&leg, reaction("rin", "2.000", "A"), NULL, 500, 500), HM_ADMIT_ROW);
  late = reaction("rlate", "3.000", "B");          /* its parent comes later */
  assert_int_equal(hm_leg_add(&leg, late, NULL, 500, 500), HM_ADMIT_ROW);
  assert_int_equal(hm_leg_derive(&leg, NULL, &ctx), 0);   /* nothing lost: no derivation */
  for (i = 0; i < HM_DECL_MAX; i++) {
    snprintf(id, sizeof id, "d%02d", i);
    hm_leg_declare(&leg, "A", id, "", 500);
  }
  assert_int_equal(leg.decl_lost, 0);
  hm_leg_declare(&leg, "A", "dlost", "", 500);
  assert_int_equal(leg.decl_lost, 1);
  assert_int_equal(leg.ndecl, HM_DECL_MAX);
  assert_int_equal(hm_leg_add(&leg, reaction("rlost", "4.000", "A"), NULL, 500, 500),
                   HM_ADMIT_CONTEXT);
  hm_leg_add(&leg, row("B", "1.500", ""), NULL, 500, 500);
  assert_int_equal(leg.rows, 4);                   /* A rin rlate B */
  assert_int_equal(hm_leg_derive(&leg, NULL, &ctx), 2);   /* rin and rlate */
  assert_string_equal(ids(ctx), "rin rlate");
  assert_int_equal(leg.rows, 2);
  history_free_messages(ctx);
  hm_leg_free(&leg);

  memset(&leg, 0, sizeof(leg));                    /* derive 0: not a page */
  hm_leg_add(&leg, row("A", "1.000", ""), NULL, 500, 500);
  leg.decl_lost = 1;
  assert_int_equal(hm_leg_add(&leg, reaction("r", "2.000", "A"), NULL, 500, 500), HM_ADMIT_ROW);
  hm_leg_free(&leg);
}

/* A REDACT is never lost to a cap: dropped as a row past the row cap, as a
 * context child past the context cap, or on the CH C row-ahead move into a
 * full context budget, its target is kept and the filter still hides it. */
static void test_leg_redact_kept_past_every_cap(void **s)
{
  struct hm_page_leg leg;
  struct HistoryMessage *page;

  (void)s;
  memset(&leg, 0, sizeof(leg));
  assert_int_equal(hm_leg_add(&leg, row("P", "1.000", ""), NULL, 1, 1), HM_ADMIT_ROW);
  assert_int_equal(hm_leg_add(&leg, typed("D1", "2.000", HISTORY_REDACT, "T1 :why"),
                              NULL, 1, 1), HM_DROP_ROW);
  hm_leg_declare(&leg, "P", "c1", "", 1);
  assert_int_equal(hm_leg_add(&leg, bare_tag("c1", "3.000"), NULL, 1, 1), HM_ADMIT_CONTEXT);
  hm_leg_declare(&leg, "P", "D2", "", 1);
  assert_int_equal(hm_leg_add(&leg, typed("D2", "4.000", HISTORY_REDACT, "T2"),
                              NULL, 1, 1), HM_DROP_CONTEXT);
  hm_leg_free(&leg);
  assert_int_equal(leg.side.n, 0);   /* freed with the leg */

  memset(&leg, 0, sizeof(leg));
  assert_int_equal(hm_leg_add(&leg, typed("D1", "2.000", HISTORY_REDACT, "T1 :why"),
                              NULL, 0, 1), HM_DROP_ROW);
  hm_leg_add(&leg, bare_tag("c1", "3.000"), NULL, 1, 0);         /* a row, the cap 1 */
  assert_int_equal(hm_leg_add(&leg, typed("D3", "5.000", HISTORY_REDACT, "T3"),
                              NULL, 2, 0), HM_ADMIT_ROW);
  hm_leg_declare(&leg, "c1", "D3", "", 0);                       /* row-ahead, ctx cap 0 */
  assert_int_equal(leg.rows, 1);
  assert_int_equal(leg.ctx, 0);
  assert_string_equal(ids(leg.msgs), "c1");
  hm_leg_add(&leg, typed("D2", "4.000", HISTORY_REDACT, "T2"), NULL, 1, 0);   /* row cap */
  assert_int_equal(leg.side.n, 3);
  assert_int_equal(leg.side.lost, 0);

  page = chain(5, typed("T1", "1.000", HISTORY_PRIVMSG, NULL),
                  typed("T2", "1.100", HISTORY_NOTICE, NULL),
                  as_ctx(bare_tag("x", "1.150")),
                  typed("T3", "1.200", HISTORY_TAGMSG, NULL),
                  typed("N", "1.300", HISTORY_PRIVMSG, NULL));
  assert_int_equal(hm_redact_filter(&page, 4, &leg.side, NULL, NULL), 1);
  assert_string_equal(ids(page), "N");
  history_free_messages(page);
  hm_leg_free(&leg);
}

/* The side set is bounded: past HM_IDSET_MAX it is lost, and a lost side
 * set makes the page's peer lists fail closed. */
static void test_idset_overflow_closed(void **s)
{
  struct hm_idset set;
  struct HistoryMessage *peer;
  char id[16];
  int i;

  (void)s;
  memset(&set, 0, sizeof(set));
  hm_idset_note_redact(&set, HISTORY_PRIVMSG, "X");   /* not a REDACT: ignored */
  assert_int_equal(set.n, 0);
  for (i = 0; i < HM_IDSET_MAX; i++) {
    snprintf(id, sizeof id, "T%04d", i);
    assert_int_equal(hm_idset_add(&set, id), 1);
  }
  assert_int_equal(set.lost, 0);
  hm_idset_note_redact(&set, HISTORY_REDACT, "ONEMORE :r");
  assert_int_equal(set.lost, 1);
  assert_int_equal(set.n, HM_IDSET_MAX);
  hm_idset_free(&set);
  assert_int_equal(set.n, 0);

  peer = chain(4, typed("M", "1.000", HISTORY_PRIVMSG, NULL),
                  typed("D", "2.000", HISTORY_REDACT, "Q"),
                  typed("J", "3.000", HISTORY_JOIN, NULL),
                  bare_tag("R", "4.000"));
  assert_int_equal(hm_fail_closed(&peer), 2);
  assert_string_equal(ids(peer), "D J");
  history_free_messages(peer);
  peer = NULL;
  assert_int_equal(hm_fail_closed(&peer), 0);
}

/* F-4's wiring: context children never count as rows -- extracting them
 * leaves the row count alone; a row that came ahead of its declaration
 * moves from the row budget to the context budget; the auto-replay
 * delivers a channel only when a row came, not context alone. */
static void test_leg_f4_wiring(void **s)
{
  struct hm_page_leg leg;
  struct HistoryMessage *ctx;

  (void)s;
  memset(&leg, 0, sizeof(leg));
  hm_leg_declare(&leg, "R", "C1", "", 500);
  hm_leg_add(&leg, bare_tag("C1", "2.000"), NULL, 500, 500);
  assert_int_equal(hm_leg_has_rows(&leg), 0);      /* context alone: no delivery */
  hm_leg_add(&leg, row("R", "1.000", ""), NULL, 500, 500);
  hm_leg_declare(&leg, "R", "C2", "", 500);
  hm_leg_add(&leg, bare_tag("C2", "2.500"), NULL, 500, 500);
  hm_leg_add(&leg, bare_tag("X", "3.000"), NULL, 500, 500);     /* a row, for now */
  assert_int_equal(leg.rows, 2);
  assert_int_equal(leg.ctx, 2);
  assert_int_equal(hm_leg_has_rows(&leg), 1);
  hm_leg_declare(&leg, "R", "X", "+draft/react=y", 500);         /* row-ahead */
  assert_int_equal(leg.rows, 1);
  assert_int_equal(leg.ctx, 3);
  assert_int_equal(leg.ndecl, 0);
  hm_leg_declare(&leg, "R", "LOST", "", 500);        /* its row never comes */
  assert_int_equal(hm_leg_forget_decl(&leg, "LOST", NULL, 0), 1);
  assert_int_equal(hm_leg_forget_decl(&leg, "LOST", NULL, 0), 0);
  assert_int_equal(leg.ndecl, 0);
  ctx = hm_leg_extract_context(&leg);
  assert_string_equal(ids(ctx), "C1 C2 X");
  assert_string_equal(ctx->next->next->ctx_parent, "R");
  assert_string_equal(ctx->next->next->client_tags, "+draft/react=y");
  assert_int_equal(leg.rows, 1);
  assert_int_equal(leg.ctx, 0);
  assert_string_equal(ids(leg.msgs), "R");
  history_free_messages(ctx);
  hm_leg_free(&leg);
}

/* F-7 for rows: a reaction that is a row of the page, to a message a
 * REDACT of the page (or the side set) names, goes too; a reaction to an
 * unredacted message stays. */
static void test_redact_filter_rows_of_redacted(void **s)
{
  struct HistoryMessage *head = chain(6,
      typed("M", "1.000", HISTORY_PRIVMSG, NULL),
      typed("D", "2.000", HISTORY_REDACT, "M"),
      reaction("Rm", "3.000", "M"),
      typed("N", "4.000", HISTORY_PRIVMSG, NULL),
      reaction("Rn", "5.000", "N"),
      reaction("Rgone", "6.000", "GONE"));
  struct hm_idset side;

  (void)s;
  memset(&side, 0, sizeof(side));
  hm_idset_add(&side, "GONE");
  assert_int_equal(hm_redact_filter(&head, 6, &side, NULL, NULL), 3);
  assert_string_equal(ids(head), "D N Rn");
  history_free_messages(head);
  hm_idset_free(&side);
}

/* A row one of whose children could not be read (history_attach_context's
 * ctx_unread) may be redacted: it goes, and its context run with it. */
static void test_redact_filter_unread_child(void **s)
{
  struct HistoryMessage *head = chain(4,
      typed("M", "1.000", HISTORY_PRIVMSG, NULL),
      as_ctx(bare_tag("R", "5.000")),
      typed("N", "2.000", HISTORY_PRIVMSG, NULL),
      as_ctx(bare_tag("R2", "6.000")));

  (void)s;
  head->ctx_unread = 1;
  assert_int_equal(hm_redact_filter(&head, 2, NULL, NULL, NULL), 2);
  assert_string_equal(ids(head), "N R2");
  history_free_messages(head);

  /* An event can never be redacted: it stays. */
  head = chain(1, typed("J", "1.000", HISTORY_JOIN, NULL));
  head->ctx_unread = 1;
  assert_int_equal(hm_redact_filter(&head, 1, NULL, NULL, NULL), 1);
  assert_string_equal(ids(head), "J");
  history_free_messages(head);
}

/* ---- W5 Task 15 fix round 2 ---- */

/* I-A(b): a REDACT whose target this request could not keep (side.lost)
 * may name a LOCAL row too (a children-leg REDACT always does; a peer
 * row's local duplicate is the one the merge keeps; a context-only page is
 * all local rows): every row of the finished page a REDACT could name is
 * withheld, local ones included.  Without lost, nothing is. */
static void test_leg_close_page_local_rows(void **s)
{
  struct hm_page_leg leg;
  struct HistoryMessage *page;

  (void)s;
  memset(&leg, 0, sizeof(leg));
  page = chain(5, typed("L1", "1.000", HISTORY_PRIVMSG, NULL),
                  as_ctx(bare_tag("Lr", "5.000")),
                  typed("J", "2.000", HISTORY_JOIN, NULL),
                  typed("D", "3.000", HISTORY_REDACT, "Q"),
                  typed("L2", "4.000", HISTORY_NOTICE, NULL));
  assert_int_equal(hm_leg_close_page(&leg, &page), 0);
  assert_string_equal(ids(page), "L1 Lr J D L2");
  leg.side.lost = 1;
  assert_int_equal(hm_leg_close_page(&leg, &page), 3);
  assert_string_equal(ids(page), "J D");
  history_free_messages(page);
  hm_leg_free(&leg);
}

/* I-A(a): a declared REDACT lost before it was read (a CH B with no slot,
 * an undecodable line) still names its target -- its declaration's parent:
 * forgetting the declaration hands it back. */
static void test_leg_forget_decl_parent(void **s)
{
  struct hm_page_leg leg;
  char parent[HISTORY_MSGID_LEN];

  (void)s;
  memset(&leg, 0, sizeof(leg));
  hm_leg_declare(&leg, "TARGET", "RD", "", 500);
  assert_int_equal(hm_leg_forget_decl(&leg, "RD", parent, sizeof parent), 1);
  assert_string_equal(parent, "TARGET");
  assert_int_equal(leg.ndecl, 0);
  assert_int_equal(hm_leg_forget_decl(&leg, "RD", parent, sizeof parent), 0);
  hm_leg_free(&leg);
}

/* I-B: the merge limit can cut a peer's REDACT row (newer) while the row
 * it names (older) stays on the page.  Every REDACT the peers sent is seeded
 * into the side set before the merge, so the filter still hides its
 * target. */
static void test_side_seeded_before_merge(void **s)
{
  struct hm_page_leg leg;
  struct HistoryMessage *merged;

  (void)s;
  memset(&leg, 0, sizeof(leg));
  hm_leg_add(&leg, typed("T", "1.000", HISTORY_PRIVMSG, NULL), NULL, 500, 500);
  hm_leg_add(&leg, typed("D", "9.000", HISTORY_REDACT, "T :spam"), NULL, 500, 500);
  hm_idset_note_list(&leg.side, leg.msgs);
  hm_idset_note_list(&leg.side, NULL);
  assert_int_equal(leg.side.n, 1);
  merged = hm_merge(NULL, leg.msgs, 1, 1);             /* AFTER: keeps the oldest */
  assert_string_equal(ids(merged), "T");
  assert_int_equal(hm_redact_filter(&merged, 1, &leg.side, NULL, NULL), 0);
  assert_null(merged);
  hm_leg_free(&leg);
}

/* Minor 1: with three or more stores two responders can each declare the
 * same child.  The second declaration must wait for its own row, not be
 * swallowed by the first responder's row (already context) -- or the
 * second copy arrives undeclared and is merged as a row. */
static void test_leg_two_responders_declare_one_child(void **s)
{
  struct hm_page_leg leg;

  (void)s;
  memset(&leg, 0, sizeof(leg));
  hm_leg_add(&leg, row("P", "1.000", ""), NULL, 500, 500);
  hm_leg_declare(&leg, "P", "X", "", 500);                       /* A */
  assert_int_equal(hm_leg_add(&leg, bare_tag("X", "5.000"), NULL, 500, 500),
                   HM_ADMIT_CONTEXT);
  hm_leg_declare(&leg, "P", "X", "", 500);                       /* B */
  assert_int_equal(leg.ndecl, 1);
  assert_int_equal(hm_leg_add(&leg, bare_tag("X", "5.000"), NULL, 500, 500),
                   HM_ADMIT_CONTEXT);
  assert_int_equal(leg.rows, 1);
  assert_int_equal(leg.ctx, 2);
  assert_int_equal(leg.ndecl, 0);
  hm_leg_free(&leg);
}

/* Minor 2: a request's CH B reassembly entries are keyed "<reqid>:<msgid>"
 * (page leg) and "<reqid>K:<msgid>" (children leg); freeing the request
 * frees exactly those. */
static void test_chunk_of_request(void **s)
{
  (void)s;
  assert_int_equal(hm_chunk_of_request("Bj12:AAAA", "Bj12"), 1);
  assert_int_equal(hm_chunk_of_request("Bj12K:AAAA", "Bj12"), 1);
  assert_int_equal(hm_chunk_of_request("Bj123:AAAA", "Bj12"), 0);
  assert_int_equal(hm_chunk_of_request("Bj12KK:AAAA", "Bj12"), 0);
  assert_int_equal(hm_chunk_of_request("Bj1:AAAA", "Bj12"), 0);
  assert_int_equal(hm_chunk_of_request("Bj12", "Bj12"), 0);
  assert_int_equal(hm_chunk_of_request(NULL, "Bj12"), 0);
  assert_int_equal(hm_chunk_of_request("Bj12:AAAA", ""), 0);
}

/* ---- W5 Task 15 fix round 3 ---- */

/* I-C: the responder's skip.  A row its attach could not fully read goes
 * with its non-REDACT context -- never its REDACTs, which may be all that
 * hides the requester's own copy.  On the children leg (stubs, never sent)
 * there is no row skip: each child is checked by itself.  A context
 * reaction the lookup does not clear (redacted, or unknown) goes. */
static void test_responder_skip_keeps_redacts(void **s)
{
  struct HistoryMessage *head = chain(6,
      typed("M", "1.000", HISTORY_PRIVMSG, NULL),
      as_ctx(bare_tag("R", "5.000")),
      as_ctx(typed("D", "6.000", HISTORY_REDACT, "M")),
      typed("N", "2.000", HISTORY_PRIVMSG, NULL),
      as_ctx(bare_tag("REDr", "7.000")),
      as_ctx(bare_tag("ok", "8.000")));

  (void)s;
  head->ctx_unread = 1;
  redacted_calls = 0;
  hm_responder_skip(&head, 1, fake_redacted, NULL);
  assert_string_equal(ids(head), "D N ok");
  assert_int_equal(redacted_calls, 2);   /* REDr, ok: R went with M unlooked */
  history_free_messages(head);

  /* The children leg: a stub with an unreadable child keeps its children,
   * each checked by itself; its REDACT always stays. */
  head = chain(4, typed("STUB", "0", HISTORY_PRIVMSG, NULL),
                  as_ctx(bare_tag("ok", "5.000")),
                  as_ctx(bare_tag("ERRx", "6.000")),
                  as_ctx(typed("D", "7.000", HISTORY_REDACT, "STUB")));
  head->ctx_unread = 1;
  redacted_calls = 0;
  hm_responder_skip(&head, 0, fake_redacted, NULL);
  assert_string_equal(ids(head), "STUB ok D");
  assert_int_equal(redacted_calls, 2);
  history_free_messages(head);

  /* An event's unread child skips nothing (it cannot be redacted). */
  head = chain(2, typed("J", "1.000", HISTORY_JOIN, NULL),
                  as_ctx(bare_tag("ok", "5.000")));
  head->ctx_unread = 1;
  hm_responder_skip(&head, 1, fake_redacted, NULL);
  assert_string_equal(ids(head), "J ok");
  history_free_messages(head);
}

/* m1: duplicates never count toward HM_IDSET_MAX -- three stores each
 * sending the same mass self-redaction must not withhold the page. */
static void test_idset_duplicates_do_not_overflow(void **s)
{
  struct hm_idset set;
  char id[16];
  int i, round;

  (void)s;
  memset(&set, 0, sizeof(set));
  for (i = 0; i < 5000; i++)
    assert_int_equal(hm_idset_add(&set, "SAME"), 1);
  assert_int_equal(set.n, 1);
  hm_idset_free(&set);

  for (round = 0; round < 3; round++)          /* three stores, one set */
    for (i = 0; i < HM_IDSET_MAX; i++) {
      snprintf(id, sizeof id, "T%04d", (i * 7 + round) % HM_IDSET_MAX);
      assert_int_equal(hm_idset_add(&set, id), 1);
    }
  assert_int_equal(set.lost, 0);
  assert_int_equal(set.n, HM_IDSET_MAX);
  assert_int_equal(hm_idset_add(&set, "NEW"), 0);   /* a distinct one past it */
  assert_int_equal(set.lost, 1);
  hm_idset_free(&set);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_redact_filter_no_cap),
    cmocka_unit_test(test_redact_filter_drops_children_of_redacted),
    cmocka_unit_test(test_redact_filter_checks_context),
    cmocka_unit_test(test_redact_filter_nothing_dropped),
    cmocka_unit_test(test_redact_filter_closed),
    cmocka_unit_test(test_page_parent_derives_context),
    cmocka_unit_test(test_fed_admit_two_budgets),
    cmocka_unit_test(test_leg_decl_remove_on_match),
    cmocka_unit_test(test_leg_fallback_flag),
    cmocka_unit_test(test_leg_redact_kept_past_every_cap),
    cmocka_unit_test(test_idset_overflow_closed),
    cmocka_unit_test(test_leg_f4_wiring),
    cmocka_unit_test(test_redact_filter_rows_of_redacted),
    cmocka_unit_test(test_redact_filter_unread_child),
    cmocka_unit_test(test_leg_close_page_local_rows),
    cmocka_unit_test(test_leg_forget_decl_parent),
    cmocka_unit_test(test_side_seeded_before_merge),
    cmocka_unit_test(test_leg_two_responders_declare_one_child),
    cmocka_unit_test(test_chunk_of_request),
    cmocka_unit_test(test_responder_skip_keeps_redacts),
    cmocka_unit_test(test_idset_duplicates_do_not_overflow),
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
