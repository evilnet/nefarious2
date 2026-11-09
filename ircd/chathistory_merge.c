/*
 * IRC - Internet Relay Chat, ircd/chathistory_merge.c
 * Copyright (C) 2026 Nefarious Development Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Merging a federated chathistory page (moved out of
 *   m_chathistory.c, where it was message_exists / merge_messages, so the
 *   merge can be unit-tested without the store).
 *
 * The requester of a federated page holds two row lists: its own store's
 * (local_msgs) and the rows its peers sent back (fed_msgs).  hm_merge
 * makes the page from both; hm_find_dup is its duplicate test, also used
 * by the context splice (hm_splice_context).  The children request's pure
 * parts live here too (W5 Task 14): which of a page's rows to ask about
 * (hm_children_wanted) and a CH Q K line's msgid list (hm_pack_ids,
 * hm_parse_ids).  So do CHATHISTORY TARGETS' (W5 Task 11): a bound's time,
 * the merge of the requester's and its peers' targets, the page, and a
 * responder's order and cut (hm_targets_*).
 */
#include "config.h"

#include "chathistory_merge.h"
#include "history.h"
#include "ircd_alloc.h"
#include "ircd_string.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

struct HistoryMessage *hm_find_dup(struct HistoryMessage *list,
                                   const struct HistoryMessage *check)
{
  struct HistoryMessage *m;
  const char *check_content = check->dyn_content ? check->dyn_content : check->content;

  for (m = list; m; m = m->next) {
    /* Exact msgid match */
    if (strcmp(m->msgid, check->msgid) == 0)
      return m;
    /* Semantic duplicate: same timestamp + sender + type + content.
     * Catches the same message stored on different servers with
     * different msgids (e.g. Bj-* on hub vs AC-* on leaf). */
    if (m->type == check->type
        && strcmp(m->timestamp, check->timestamp) == 0
        && strcmp(m->sender, check->sender) == 0) {
      const char *m_content = m->dyn_content ? m->dyn_content : m->content;
      if (strcmp(m_content, check_content) == 0)
        return m;
    }
  }
  return NULL;
}

struct HistoryMessage *hm_merge(struct HistoryMessage *list1,
                                struct HistoryMessage *list2,
                                int limit, int keep_oldest)
{
  struct HistoryMessage *result = NULL, *tail = NULL;
  struct HistoryMessage *p1 = list1, *p2 = list2;
  int count = 0;

  /* Merge-sort both lists by timestamp (both are already chronological).
   * Collect ALL unique messages first, then truncate to keep the N most
   * recent. The old code greedily filled from list1 first, which meant
   * stale local messages (e.g. typing indicators) could crowd out newer
   * federated messages. */

  /* Step 1: Merge both lists into one sorted list (no limit yet) */
  while (p1 || p2) {
    struct HistoryMessage *pick, *kept, *copy;
    if (!p1) {
      pick = p2; p2 = p2->next;
    } else if (!p2) {
      pick = p1; p1 = p1->next;
    } else {
      /* Same-millisecond rows from two legs must land in store-key
       * order (msgid), or the client's next exact AFTER seek steps past
       * the sibling the merge emitted first (re-review R10). */
      int c = strcmp(p1->timestamp, p2->timestamp);
      if (c == 0)
        c = strcmp(p1->msgid, p2->msgid);
      if (c <= 0) {
        pick = p1; p1 = p1->next;
      } else {
        pick = p2; p2 = p2->next;
      }
    }

    /* Deduplicate.  The dropped copy may be the only one that kept the
     * message's client-only tags: a local row stored before relays kept
     * them (W5 Task 1), or one a peer sent back with ,C while the kept
     * copy came from an older peer that sends none.  The kept row takes
     * them then, and never loses tags of its own. */
    kept = hm_find_dup(result, pick);
    if (kept) {
      if (!kept->client_tags[0] && pick->client_tags[0])
        ircd_strncpy(kept->client_tags, pick->client_tags, sizeof(kept->client_tags));
      continue;
    }

    copy = (struct HistoryMessage *)MyCalloc(1, sizeof(*copy));
    memcpy(copy, pick, sizeof(*copy));
    copy->next = NULL;
    /* Ownership of the heap content moves to the copy: the merged list
     * is handed to the replay engine, which frees it with
     * history_free_messages, and the source lists are freed by
     * free_fed_request afterwards.  Leaving both pointing at the same
     * raw_content/dyn_content was a double free on every federated page
     * with a compressed (>256 B) or multiline local row (2026-09-06).
     * A dropped duplicate (above) keeps its own: its source frees it. */
    pick->raw_content = NULL;
    pick->raw_content_len = 0;
    pick->dyn_content = NULL;
    pick->dyn_content_len = 0;
    if (!result) {
      result = tail = copy;
    } else {
      tail->next = copy;
      tail = copy;
    }
    count++;
  }

  /* Step 2: trim to `limit`.  Direction matters: LATEST/BEFORE and a
   * descending BETWEEN keep the NEWEST `limit` (drop from the front);
   * AFTER and an ascending BETWEEN keep the OLDEST `limit` (drop from
   * the tail) -- keeping the newest for a forward query dropped the
   * rows right after the anchor, so the client's next AFTER started
   * past them (audit 2026-09-06 #9).  An AROUND page is not cut here:
   * its caller merges it uncut and centres it on its reference
   * (hm_trim_around; W5 Push D -- keeping the newest drifted it off). */
  if (count > limit && result) {
    if (keep_oldest) {
      struct HistoryMessage *m = result;
      int i = 1;
      while (m && i < limit) { m = m->next; i++; }
      if (m && m->next) {
        struct HistoryMessage *drop = m->next;
        m->next = NULL;
        history_free_messages(drop);
      }
    } else {
      while (count > limit && result) {
        struct HistoryMessage *old = result;
        result = result->next;
        old->next = NULL;
        history_free_messages(old);
        count--;
      }
    }
  }

  return result;
}

/** Epoch ms of a row's "sec.mmm" timestamp (a shorter fraction is scaled:
 * "sec.5" is 500 ms). */
static uint64_t hm_ts_ms(const char *ts)
{
  char *p;
  uint64_t ms = (uint64_t)strtoull(ts, &p, 10) * 1000ULL, frac = 0;
  int d;

  if (*p == '.')
    p++;
  for (d = 0; d < 3; d++) {
    frac *= 10;
    if (*p >= '0' && *p <= '9')
      frac += (uint64_t)(*p++ - '0');
  }
  return ms + frac;
}

/** Is @a m before an AROUND reference (hm_trim_around)? */
static int hm_before_ref(const struct HistoryMessage *m, uint64_t ref_ms,
                         const char *ref_msgid)
{
  uint64_t t = hm_ts_ms(m->timestamp);

  if (t != ref_ms)
    return t < ref_ms;
  return ref_msgid && ref_msgid[0] && strcmp(m->msgid, ref_msgid) < 0;
}

struct HistoryMessage *hm_trim_around(struct HistoryMessage *list, int limit,
                                      uint64_t ref_ms, const char *ref_msgid)
{
  struct HistoryMessage *m, **pp;
  int before = 0, after = 0, keep_before, keep_after, drop_before;

  if (limit < 0)
    limit = 0;
  for (m = list; m; m = m->next) {
    if (hm_before_ref(m, ref_ms, ref_msgid))
      before++;
    else
      after++;
  }
  keep_before = before < limit / 2 ? before : limit / 2;
  keep_after = after < limit - keep_before ? after : limit - keep_before;
  /* The list is in time order: the before rows to drop are the first ones
   * met (the oldest), the after rows to keep the first ones met. */
  drop_before = before - keep_before;
  pp = &list;
  while ((m = *pp)) {
    int drop;

    if (hm_before_ref(m, ref_ms, ref_msgid)) {
      drop = drop_before > 0;
      if (drop)
        drop_before--;
    } else {
      drop = keep_after <= 0;
      if (!drop)
        keep_after--;
    }
    if (drop) {
      *pp = m->next;
      m->next = NULL;
      history_free_messages(m);
    } else
      pp = &m->next;
  }
  return list;
}

const char *hm_context_parent(const struct HistoryMessage *m, char *buf,
                              size_t buflen)
{
  /* history.c's extract_reply_tag: the ratified +reply wins over the
   * legacy +draft/reply, each only at the start of the list or after a
   * separator. */
  static const char *const needles[] = { "+reply=", "+draft/reply=" };
  const char *p, *end;
  size_t i, len;

  if (!m || !buf || !buflen)
    return NULL;
  if (m->type == HISTORY_REDACT) {
    p = m->dyn_content ? m->dyn_content : m->content;
    end = strchr(p, ' ');
    len = end ? (size_t)(end - p) : strlen(p);
    if (len == 0 || len >= buflen)
      return NULL;
    memcpy(buf, p, len);
    buf[len] = '\0';
    return buf;
  }
  if (m->type != HISTORY_TAGMSG || !m->client_tags[0])
    return NULL;
  for (i = 0; i < sizeof(needles) / sizeof(needles[0]); i++) {
    size_t nlen = strlen(needles[i]);

    for (p = m->client_tags; (p = strstr(p, needles[i])) != NULL; p += nlen) {
      if (p != m->client_tags && p[-1] != ';')
        continue;
      p += nlen;
      end = strchr(p, ';');
      len = end ? (size_t)(end - p) : strlen(p);
      if (len == 0 || len >= buflen)
        return NULL;
      memcpy(buf, p, len);
      buf[len] = '\0';
      return buf;
    }
  }
  return NULL;
}

void hm_splice_context(struct HistoryMessage *merged,
                       struct HistoryMessage *ctx_list)
{
  struct HistoryMessage *ctx = ctx_list;

  while (ctx) {
    struct HistoryMessage *next_ctx = ctx->next;
    struct HistoryMessage *parent = NULL, *m;

    ctx->next = NULL;

    if (!hm_find_dup(merged, ctx)) {
      for (m = merged; m; m = m->next) {
        if (!m->is_context && strcmp(m->msgid, ctx->ctx_parent) == 0) {
          parent = m;
          break;
        }
      }
    }

    if (parent) {
      /* Insert after the parent's existing context run */
      struct HistoryMessage *ins = parent;
      while (ins->next && ins->next->is_context)
        ins = ins->next;
      ctx->next = ins->next;
      ins->next = ctx;
    } else {
      history_free_messages(ctx);
    }
    ctx = next_ctx;
  }
}

int hm_children_wanted(const struct HistoryMessage *rows,
                       int (*received)(uint64_t ms, void *ctx), void *ctx,
                       const char **ids, int max)
{
  const struct HistoryMessage *m, **v;
  int n = 0, i, cut = -1, out = 0;

  if (!rows || !received || !ids || max <= 0)
    return 0;
  for (m = rows; m; m = m->next)
    if (!m->is_context)
      n++;
  if (n == 0)
    return 0;
  v = (const struct HistoryMessage **)MyMalloc((size_t)n * sizeof(*v));
  for (i = 0, m = rows; m; m = m->next)
    if (!m->is_context)
      v[i++] = m;
  /* received() is monotone in the row's time (a later start is a
   * sub-range of an earlier one): every row up to the newest rejected one
   * is rejected, every row after it passes.  So the oldest row decides
   * whether anything is wanted, the newest whether everything is, and
   * between them a bisection finds the cut: at most ceil(log2 n) + 2
   * calls (each reads the window record and scans every storage peer's
   * absences; fix round 1). */
  if (!received(hm_ts_ms(v[0]->timestamp), ctx)) {
    if (n == 1 || !received(hm_ts_ms(v[n - 1]->timestamp), ctx))
      cut = n - 1;
    else {
      int lo = 0, hi = n - 1;   /* v[lo] rejected, v[hi] passes */
      while (hi - lo > 1) {
        int mid = lo + (hi - lo) / 2;
        if (received(hm_ts_ms(v[mid]->timestamp), ctx))
          hi = mid;
        else
          lo = mid;
      }
      cut = lo;
    }
  }
  for (i = 0; i <= cut && out < max; i++)
    ids[out++] = v[i]->msgid;
  MyFree(v);
  return out;
}

int hm_pack_ids(const char *const *ids, int n, int from, size_t room,
                char *out, size_t outsz)
{
  size_t len = 0;
  int k = 0, i;

  if (!out || !outsz)
    return 0;
  out[0] = '\0';
  if (!ids || from < 0)
    return 0;
  for (i = from; i < n; i++) {
    size_t l = strlen(ids[i]);
    size_t need = len + (k ? 1 : 0) + l;

    if (need > room || need + 1 > outsz)
      break;
    if (k)
      out[len++] = ' ';
    memcpy(out + len, ids[i], l);
    len += l;
    out[len] = '\0';
    k++;
  }
  return k;
}

int hm_parse_ids(char *list, const char **ids, int max)
{
  char *p = list;
  int n = 0;

  if (!list || !ids || max <= 0)
    return 0;
  while (*p && n < max) {
    char *tok;
    size_t len;

    while (*p == ' ')
      p++;
    if (!*p)
      break;
    tok = p;
    while (*p && *p != ' ')
      p++;
    len = (size_t)(p - tok);
    if (*p)
      *p++ = '\0';
    if (len < HISTORY_MSGID_LEN)
      ids[n++] = tok;
  }
  return n;
}

/* ---- W5 Task 15: redaction and context on history pages ---- */

/** Can a REDACT name @a m?  redact_authorize's rule: a PRIVMSG, a NOTICE,
 * a TAGMSG or a stored multiline. */
static int hm_redactable(const struct HistoryMessage *m)
{
  return m->type == HISTORY_PRIVMSG || m->type == HISTORY_NOTICE
         || m->type == HISTORY_TAGMSG || m->type == HISTORY_MULTILINE;
}

/** qsort/bsearch order of the REDACT target set. */
static int hm_id_cmp(const void *a, const void *b)
{
  return strcmp((const char *)a, (const char *)b);
}

/** The walk of hm_redact_filter and hm_redact_filter_closed: @a set holds
 * @a nset sorted names, or @a closed names every redactable entry.  A row
 * (not context) ends the context run of the row before it, so
 * @a parent_gone says whether the run being walked hangs on a row dropped
 * here. */
static int hm_redact_walk(struct HistoryMessage **head, int count,
                          const char (*set)[HISTORY_MSGID_LEN], int nset,
                          int closed, hm_redacted_fn redacted, void *arg)
{
  struct HistoryMessage **pp = head;
  int kept = 0, dropped = 0, parent_gone = 0;

  while (*pp) {
    struct HistoryMessage *cur = *pp;
    char parent[HISTORY_MSGID_LEN];
    int drop = 0;

    if (!cur->is_context)
      parent_gone = 0;
    if (cur->type != HISTORY_REDACT) {
      if (hm_redactable(cur)
          && (closed || (nset > 0 && bsearch(cur->msgid, set, (size_t)nset,
                                             sizeof(set[0]), hm_id_cmp))))
        drop = 1;   /* F-6: a REDACT of the page names it */
      else if (!cur->is_context && cur->ctx_unread && hm_redactable(cur))
        drop = 1;   /* a child of it could not be read: it may be redacted */
      else if (cur->is_context && parent_gone)
        drop = 1;   /* F-7: the row it hangs on went for redaction */
      else if (cur->type == HISTORY_TAGMSG && nset > 0
               && hm_context_parent(cur, parent, sizeof(parent))
               && bsearch(parent, set, (size_t)nset, sizeof(set[0]), hm_id_cmp))
        drop = 1;   /* F-7, a reaction row too: what it reacts to is redacted */
      else if (cur->is_context && redacted && hm_redactable(cur)
               && redacted(cur, arg) != 0)
        drop = 1;   /* F-2: redacted here, or not provably not */
      if (drop && !cur->is_context)
        parent_gone = 1;
    }
    if (drop) {
      *pp = cur->next;
      cur->next = NULL;
      history_free_messages(cur);
      dropped++;
    } else {
      pp = &cur->next;
      kept++;
    }
  }
  return dropped ? kept : count;
}

int hm_redact_filter_closed(struct HistoryMessage **head, int count)
{
  if (!head || !*head || count <= 0)
    return count;
  return hm_redact_walk(head, count, NULL, 0, 1, NULL, NULL);
}

int hm_fail_closed(struct HistoryMessage **list)
{
  struct HistoryMessage *m;
  int before = 0, after = 0;

  if (!list || !*list)
    return 0;
  for (m = *list; m; m = m->next)
    before++;
  hm_redact_walk(list, before, NULL, 0, 1, NULL, NULL);
  for (m = *list; m; m = m->next)
    after++;
  return before - after;
}

int hm_redact_filter(struct HistoryMessage **head, int count,
                     const struct hm_idset *extra,
                     hm_redacted_fn redacted, void *arg)
{
  struct HistoryMessage *m;
  char (*set)[HISTORY_MSGID_LEN] = NULL;
  int n = 0, nset = 0, rc;

  if (!head || !*head || count <= 0)
    return count;

  /* The targets of the page's REDACT entries, as many as it carries (F-6:
   * the old fixed table of 100 showed the redacted originals past it),
   * and of the REDACTs dropped for budget (@a extra). */
  for (m = *head; m; m = m->next)
    if (m->type == HISTORY_REDACT)
      n++;
  if (extra)
    n += extra->n;
  if (n > 0) {
    set = (char (*)[HISTORY_MSGID_LEN])MyMalloc((size_t)n * sizeof(*set));
    /* MyMalloc's out-of-memory handler does not return; were it to, no
     * redacted text may show for want of the set. */
    if (!set)
      return hm_redact_filter_closed(head, count);
    for (m = *head; m; m = m->next)
      if (m->type == HISTORY_REDACT
          && hm_context_parent(m, set[nset], sizeof(set[nset])))
        nset++;
    if (extra && extra->n > 0) {
      memcpy(set[nset], extra->ids, (size_t)extra->n * sizeof(*set));
      nset += extra->n;
    }
    qsort(set, (size_t)nset, sizeof(*set), hm_id_cmp);
  }
  rc = hm_redact_walk(head, count, (const char (*)[HISTORY_MSGID_LEN])set,
                      nset, 0, redacted, arg);
  if (set)
    MyFree(set);
  return rc;
}

/** Sort @a s and drop its duplicates; all of it is then the sorted prefix. */
static void hm_idset_compact(struct hm_idset *s)
{
  int i, w;

  if (s->n > 1) {
    qsort(s->ids, (size_t)s->n, sizeof(*s->ids), hm_id_cmp);
    for (i = 1, w = 1; i < s->n; i++) {
      if (strcmp(s->ids[i], s->ids[w - 1]) == 0)
        continue;
      if (w != i)
        memcpy(s->ids[w], s->ids[i], sizeof(*s->ids));
      w++;
    }
    s->n = w;
  }
  s->nsorted = s->n;
}

/** Is @a id in @a s?  A bsearch of the sorted prefix, then a scan of the
 * short unsorted tail (at most HM_IDSET_TAIL). */
static int hm_idset_has(const struct hm_idset *s, const char *id)
{
  int i;

  if (s->nsorted > 0
      && bsearch(id, s->ids, (size_t)s->nsorted, sizeof(*s->ids), hm_id_cmp))
    return 1;
  for (i = s->nsorted; i < s->n; i++)
    if (strcmp(s->ids[i], id) == 0)
      return 1;
  return 0;
}

int hm_idset_add(struct hm_idset *s, const char *id)
{
  char key[HISTORY_MSGID_LEN];

  if (!s || !id || !id[0])
    return 0;
  /* A target already kept is not kept twice: duplicates -- the same
   * REDACT from three stores, a row and its seeded copy -- never count
   * toward HM_IDSET_MAX (fix round 3).  Lookups stay cheap: the set is
   * sorted whenever its unsorted tail reaches HM_IDSET_TAIL. */
  ircd_strncpy(key, id, sizeof(key));
  if (hm_idset_has(s, key))
    return 1;
  if (s->n - s->nsorted >= HM_IDSET_TAIL || s->n >= HM_IDSET_MAX)
    hm_idset_compact(s);
  if (s->n >= HM_IDSET_MAX) {
    s->lost = 1;
    return 0;
  }
  if (s->n >= s->cap) {
    int cap = s->cap ? s->cap * 2 : 16;
    if (cap > HM_IDSET_MAX)
      cap = HM_IDSET_MAX;
    s->ids = (char (*)[HISTORY_MSGID_LEN])MyRealloc(s->ids, (size_t)cap * sizeof(*s->ids));
    s->cap = cap;
  }
  memcpy(s->ids[s->n], key, sizeof(key));
  s->n++;
  return 1;
}

void hm_idset_note_redact(struct hm_idset *s, int type, const char *content)
{
  char id[HISTORY_MSGID_LEN];
  const char *end;
  size_t len;

  if (!s || type != HISTORY_REDACT || !content)
    return;
  /* hm_context_parent's REDACT rule: the first content word. */
  end = strchr(content, ' ');
  len = end ? (size_t)(end - content) : strlen(content);
  if (len == 0 || len >= sizeof(id))
    return;   /* names nothing: hides nothing */
  memcpy(id, content, len);
  id[len] = '\0';
  hm_idset_add(s, id);
}

void hm_idset_note_list(struct hm_idset *s, const struct HistoryMessage *list)
{
  const struct HistoryMessage *m;

  for (m = list; m; m = m->next)
    if (m->type == HISTORY_REDACT)
      hm_idset_note_redact(s, m->type, m->dyn_content ? m->dyn_content : m->content);
}

void hm_idset_free(struct hm_idset *s)
{
  if (!s)
    return;
  if (s->ids)
    MyFree(s->ids);
  s->ids = NULL;
  s->n = s->cap = s->nsorted = 0;
  s->lost = 0;
}

const char *hm_page_parent(const struct HistoryMessage *m,
                           const struct HistoryMessage *local,
                           const struct HistoryMessage *peer,
                           char *buf, size_t buflen)
{
  const struct HistoryMessage *r;
  char own[HISTORY_MSGID_LEN];

  if (!m || !hm_context_parent(m, buf, buflen))
    return NULL;
  /* A copy of a local row stays a row: hm_merge keeps one and lends it
   * the other's tags (hm_find_dup only reads the list). */
  if (local && hm_find_dup((struct HistoryMessage *)local, m))
    return NULL;
  for (r = local; r; r = r->next)
    if (!r->is_context && strcmp(r->msgid, buf) == 0)
      return buf;
  for (r = peer; r; r = r->next)
    if (r != m && !r->is_context && strcmp(r->msgid, buf) == 0
        && !hm_context_parent(r, own, sizeof(own)))
      return buf;
  return NULL;
}

int hm_derive_context(struct HistoryMessage **peer,
                      const struct HistoryMessage *local,
                      struct HistoryMessage **ctx_list)
{
  struct HistoryMessage **pp, **tp;
  int moved = 0;

  if (!peer || !ctx_list)
    return 0;
  for (tp = ctx_list; *tp; tp = &(*tp)->next)
    ;
  pp = peer;
  while (*pp) {
    struct HistoryMessage *m = *pp;
    char parent[HISTORY_MSGID_LEN];

    if (!m->is_context && hm_page_parent(m, local, *peer, parent, sizeof(parent))) {
      *pp = m->next;
      m->next = NULL;
      m->is_context = 1;
      ircd_strncpy(m->ctx_parent, parent, sizeof(m->ctx_parent));
      *tp = m;
      tp = &m->next;
      moved++;
    } else
      pp = &m->next;
  }
  return moved;
}

enum hm_admit hm_fed_admit(int is_context, int *rows, int *ctx,
                           int row_max, int ctx_max)
{
  if (is_context) {
    if (*ctx >= ctx_max)
      return HM_DROP_CONTEXT;
    (*ctx)++;
    return HM_ADMIT_CONTEXT;
  }
  if (*rows >= row_max)
    return HM_DROP_ROW;
  (*rows)++;
  return HM_ADMIT_ROW;
}

/** The declaration naming @a child, taken out of @a leg's table
 * (remove-on-match).  @return 1 found (parent/tags copied), else 0. */
static int hm_leg_take_decl(struct hm_page_leg *leg, const char *child,
                            char *parent, size_t plen, char *tags, size_t tlen)
{
  int i;

  for (i = 0; i < leg->ndecl; i++) {
    if (strcmp(leg->decl[i].child, child) == 0) {
      ircd_strncpy(parent, leg->decl[i].parent, plen);
      ircd_strncpy(tags, leg->decl[i].tags, tlen);
      leg->decl[i] = leg->decl[--leg->ndecl];
      return 1;
    }
  }
  return 0;
}

enum hm_admit hm_leg_add(struct hm_page_leg *leg, struct HistoryMessage *msg,
                         const struct HistoryMessage *local,
                         int row_max, int ctx_max)
{
  char parent[HISTORY_MSGID_LEN], tags[sizeof(leg->decl[0].tags)];
  struct HistoryMessage **tp;
  enum hm_admit a;

  if (hm_leg_take_decl(leg, msg->msgid, parent, sizeof(parent), tags, sizeof(tags))) {
    msg->is_context = 1;
    ircd_strncpy(msg->ctx_parent, parent, sizeof(msg->ctx_parent));
    if (tags[0] && !msg->client_tags[0])
      ircd_strncpy(msg->client_tags, tags, sizeof(msg->client_tags));
  } else if (leg->derive && leg->decl_lost
             && hm_page_parent(msg, local, leg->msgs, parent, sizeof(parent))) {
    /* F-3's fallback: its declaration may be the one the full table lost */
    msg->is_context = 1;
    ircd_strncpy(msg->ctx_parent, parent, sizeof(msg->ctx_parent));
  }

  a = hm_fed_admit(msg->is_context, &leg->rows, &leg->ctx, row_max, ctx_max);
  if (a == HM_DROP_ROW || a == HM_DROP_CONTEXT) {
    hm_idset_note_redact(&leg->side, msg->type,
                         msg->dyn_content ? msg->dyn_content : msg->content);
    history_free_messages(msg);
    return a;
  }
  msg->next = NULL;
  for (tp = &leg->msgs; *tp; tp = &(*tp)->next)
    ;
  *tp = msg;
  return a;
}

void hm_leg_declare(struct hm_page_leg *leg, const char *parent,
                    const char *child, const char *tags, int ctx_max)
{
  struct HistoryMessage **pp, *m;

  /* The row came first: it is the child.  A row counted as one moves to the
   * context budget, and is dropped when that is full (never partial). */
  for (pp = &leg->msgs; (m = *pp); pp = &m->next) {
    /* A row already context is another responder's copy: this
     * declaration waits for its own row. */
    if (strcmp(m->msgid, child) != 0 || m->is_context)
      continue;
    leg->rows--;
    if (hm_fed_admit(1, &leg->rows, &leg->ctx, 0, ctx_max) == HM_DROP_CONTEXT) {
      *pp = m->next;
      m->next = NULL;
      hm_idset_note_redact(&leg->side, m->type,
                           m->dyn_content ? m->dyn_content : m->content);
      history_free_messages(m);
      return;
    }
    m->is_context = 1;
    ircd_strncpy(m->ctx_parent, parent, sizeof(m->ctx_parent));
    if (tags && tags[0] && !m->client_tags[0])
      ircd_strncpy(m->client_tags, tags, sizeof(m->client_tags));
    return;
  }

  if (leg->ndecl >= HM_DECL_MAX) {
    leg->decl_lost = 1;   /* its row will come undeclared: F-3's fallback */
    return;
  }
  ircd_strncpy(leg->decl[leg->ndecl].child, child, sizeof(leg->decl[0].child));
  ircd_strncpy(leg->decl[leg->ndecl].parent, parent, sizeof(leg->decl[0].parent));
  ircd_strncpy(leg->decl[leg->ndecl].tags, tags ? tags : "", sizeof(leg->decl[0].tags));
  leg->ndecl++;
}

int hm_leg_forget_decl(struct hm_page_leg *leg, const char *child,
                       char *parent, size_t plen)
{
  char p[HISTORY_MSGID_LEN], tags[sizeof(leg->decl[0].tags)];

  if (!hm_leg_take_decl(leg, child, p, sizeof(p), tags, sizeof(tags)))
    return 0;
  if (parent && plen)
    ircd_strncpy(parent, p, plen);
  return 1;
}

int hm_leg_close_page(const struct hm_page_leg *leg, struct HistoryMessage **page)
{
  if (!leg->side.lost)
    return 0;
  return hm_fail_closed(page);
}

void hm_responder_skip(struct HistoryMessage **head, int skip_unread_rows,
                       hm_redacted_fn redacted, void *arg)
{
  struct HistoryMessage **pp, *m;
  int skip_run = 0;

  for (pp = head; (m = *pp); ) {
    int drop = 0;

    if (!m->is_context) {
      skip_run = skip_unread_rows && m->ctx_unread && hm_redactable(m);
      drop = skip_run;
    } else if (m->type != HISTORY_REDACT) {
      /* The skipped row's reactions go with it, unlooked; any other's go
       * unless the lookup clears them. */
      drop = skip_run || (redacted && redacted(m, arg) != 0);
    }
    /* A REDACT entry always stays.  Its row skipped, send_ch_rows declares
     * it under the row before (or sends it bare when none came first): its
     * target still reaches the requester's redacted set by its content. */
    if (drop) {
      *pp = m->next;
      m->next = NULL;
      history_free_messages(m);
    } else
      pp = &m->next;
  }
}

int hm_chunk_of_request(const char *key, const char *reqid)
{
  size_t n;

  if (!key || !reqid || !reqid[0])
    return 0;
  n = strlen(reqid);
  if (strncmp(key, reqid, n) != 0)
    return 0;
  if (key[n] == 'K')
    n++;
  return key[n] == ':';
}

struct HistoryMessage *hm_leg_extract_context(struct hm_page_leg *leg)
{
  struct HistoryMessage **pp = &leg->msgs, *head = NULL, **tp = &head;

  while (*pp) {
    struct HistoryMessage *m = *pp;
    if (m->is_context && m->ctx_parent[0]) {
      *pp = m->next;
      m->next = NULL;
      *tp = m;
      tp = &m->next;
      leg->ctx--;   /* never counted as a row */
    } else
      pp = &m->next;
  }
  return head;
}

int hm_leg_derive(struct hm_page_leg *leg, const struct HistoryMessage *local,
                  struct HistoryMessage **ctx_list)
{
  int moved;

  if (!leg->derive || !leg->decl_lost)
    return 0;
  moved = hm_derive_context(&leg->msgs, local, ctx_list);
  leg->rows -= moved;
  return moved;
}

int hm_leg_has_rows(const struct hm_page_leg *leg)
{
  return leg->rows > 0 && leg->msgs != NULL;
}

void hm_leg_free(struct hm_page_leg *leg)
{
  if (leg->msgs)
    history_free_messages(leg->msgs);
  leg->msgs = NULL;
  leg->rows = leg->ctx = 0;
  leg->ndecl = 0;
  leg->decl_lost = 0;
  hm_idset_free(&leg->side);
}

/* ------------------------------------------------------------------ */
/* CHATHISTORY TARGETS (W5 Task 11; chathistory_merge.h)               */
/* ------------------------------------------------------------------ */

/** The largest whole second whose ms (with a .999 fraction) fits a
 * uint64_t: a bound past it is clamped, never wrapped. */
#define HM_SEC_MAX (UINT64_MAX / 1000ULL - 1ULL)

/** Days in month @a mo (1-12) of year @a y (proleptic Gregorian). */
static int hm_month_days(long y, long mo)
{
  static const int days[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
  if (mo == 2 && ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0))
    return 29;
  return days[mo - 1];
}

/** Read @a n digits at @a p as a number; -1 when one is not a digit. */
static long hm_digits(const char *p, int n)
{
  long v = 0;
  int i;
  for (i = 0; i < n; i++) {
    if (p[i] < '0' || p[i] > '9')
      return -1;
    v = v * 10 + (p[i] - '0');
  }
  return v;
}

int hm_targets_ref_ms(const char *ref, uint64_t *ms)
{
  const char *p;
  uint64_t frac = 0;
  int d;

  if (!ref || !*ref || !ms)
    return -1;
  if (strlen(ref) >= 19 && ref[4] == '-' && ref[7] == '-' && ref[10] == 'T'
      && ref[13] == ':' && ref[16] == ':') {
    /* ISO 8601, UTC: YYYY-MM-DDThh:mm:ss[.fff...][Z] */
    struct tm tm;
    long y = hm_digits(ref, 4), mo = hm_digits(ref + 5, 2), da = hm_digits(ref + 8, 2);
    long h = hm_digits(ref + 11, 2), mi = hm_digits(ref + 14, 2), se = hm_digits(ref + 17, 2);
    time_t t;

    /* A day its month does not have is refused: timegm would roll it
     * over ("Feb 30" is March 2), paging from a time the client never
     * meant.  A leap second (:60) is accepted and is the next second. */
    if (y < 0 || mo < 1 || mo > 12 || da < 1 || da > hm_month_days(y, mo)
        || h < 0 || h > 23 || mi < 0 || mi > 59 || se < 0 || se > 60)
      return -1;
    p = ref + 19;
    if (*p == '.') {
      /* A decimal fraction: ".5" is 500 ms, ".123456" is 123 ms. */
      p++;
      if (*p < '0' || *p > '9')
        return -1;
      for (d = 0; *p >= '0' && *p <= '9'; p++, d++)
        if (d < 3)
          frac = frac * 10 + (uint64_t)(*p - '0');
      for (; d < 3; d++)
        frac *= 10;
    }
    if (*p == 'Z')
      p++;
    if (*p)
      return -1;
    memset(&tm, 0, sizeof tm);
    tm.tm_year = (int)(y - 1900);
    tm.tm_mon = (int)(mo - 1);
    tm.tm_mday = (int)da;
    tm.tm_hour = (int)h;
    tm.tm_min = (int)mi;
    tm.tm_sec = (int)se;
    t = timegm(&tm);
    if (t == (time_t)-1 && y != 1969)
      return -1;
    *ms = t < 0 ? 0 : (uint64_t)t * 1000ULL + frac;
    return 0;
  }
  /* "sec[.mmm]": seconds past HM_SEC_MAX clamp to it (a far bound),
   * never wrap through the x1000. */
  {
    uint64_t sec = 0;
    int clamped = 0;
    for (p = ref; *p >= '0' && *p <= '9'; p++) {
      unsigned int dgt = (unsigned int)(*p - '0');
      if (!clamped && sec > (HM_SEC_MAX - dgt) / 10ULL)
        clamped = 1;
      if (!clamped)
        sec = sec * 10ULL + dgt;
    }
    if (p == ref)
      return -1;
    if (*p == '.') {
      for (p++, d = 0; *p >= '0' && *p <= '9'; p++, d++)
        if (d < 3)
          frac = frac * 10 + (uint64_t)(*p - '0');
      for (; d < 3; d++)
        frac *= 10;
    }
    if (*p)
      return -1;
    if (clamped) {
      sec = HM_SEC_MAX;
      frac = 999;
    }
    *ms = sec * 1000ULL + frac;
    return 0;
  }
}

uint64_t hm_targets_stamp_ms(const char *stamp)
{
  return stamp ? hm_ts_ms(stamp) : 0;
}

/** A target and its stamp in ms, for sorting. */
struct hm_tent {
  struct HistoryTarget *t;
  uint64_t ms;
};

/** Ascending stamp, then folded name (then bytes, so two spellings of
 * one name, which a merged list never holds, still order). */
static int hm_tent_asc(const void *a, const void *b)
{
  const struct hm_tent *x = (const struct hm_tent *)a;
  const struct hm_tent *y = (const struct hm_tent *)b;
  int c;
  if (x->ms != y->ms)
    return x->ms < y->ms ? -1 : 1;
  c = ircd_strcmp(x->t->target, y->t->target);
  return c ? c : strcmp(x->t->target, y->t->target);
}

/** Descending stamp, then folded name ascending. */
static int hm_tent_desc(const void *a, const void *b)
{
  const struct hm_tent *x = (const struct hm_tent *)a;
  const struct hm_tent *y = (const struct hm_tent *)b;
  int c;
  if (x->ms != y->ms)
    return x->ms > y->ms ? -1 : 1;
  c = ircd_strcmp(x->t->target, y->t->target);
  return c ? c : strcmp(x->t->target, y->t->target);
}

/** Folded name, then the latest stamp first (hm_targets_merge). */
static int hm_tent_name(const void *a, const void *b)
{
  const struct hm_tent *x = (const struct hm_tent *)a;
  const struct hm_tent *y = (const struct hm_tent *)b;
  int c = ircd_strcmp(x->t->target, y->t->target);
  if (c)
    return c;
  if (x->ms != y->ms)
    return x->ms > y->ms ? -1 : 1;
  return strcmp(x->t->target, y->t->target);
}

/** The list as an array (the nodes are not copied); its length in @a n. */
static struct hm_tent *hm_tent_array(struct HistoryTarget *list, int *n)
{
  struct HistoryTarget *t;
  struct hm_tent *arr;
  int i = 0;

  *n = 0;
  for (t = list; t; t = t->next)
    (*n)++;
  if (*n == 0)
    return NULL;
  arr = (struct hm_tent *)MyMalloc(sizeof(*arr) * (size_t)*n);
  for (t = list; t; t = t->next, i++) {
    arr[i].t = t;
    arr[i].ms = hm_ts_ms(t->last_timestamp);
  }
  return arr;
}

/** Relink the entries @a keep marks, in array order; free the others. */
static struct HistoryTarget *hm_tent_relink(struct hm_tent *arr, const char *keep, int n)
{
  struct HistoryTarget *head = NULL, **tail = &head;
  int i;
  for (i = 0; i < n; i++) {
    if (keep[i]) {
      *tail = arr[i].t;
      tail = &arr[i].t->next;
    } else {
      MyFree(arr[i].t);
    }
  }
  *tail = NULL;
  return head;
}

struct HistoryTarget *hm_targets_merge(struct HistoryTarget *a, struct HistoryTarget *b)
{
  struct HistoryTarget **tail = &a;
  struct hm_tent *arr;
  char *keep;
  int n, i;

  while (*tail)
    tail = &(*tail)->next;
  *tail = b;
  arr = hm_tent_array(a, &n);
  if (!arr)
    return NULL;
  qsort(arr, (size_t)n, sizeof(*arr), hm_tent_name);
  keep = (char *)MyCalloc(1, (size_t)n);
  for (i = 0; i < n; i++)
    keep[i] = (i == 0 || ircd_strcmp(arr[i].t->target, arr[i - 1].t->target) != 0);
  a = hm_tent_relink(arr, keep, n);
  MyFree(keep);
  MyFree(arr);
  return a;
}

int hm_targets_page(struct HistoryTarget **list, uint64_t first_ms, uint64_t second_ms,
                    int limit, hm_target_ok_fn ok, void *ctx, int *more)
{
  uint64_t lo = first_ms < second_ms ? first_ms : second_ms;
  uint64_t hi = first_ms < second_ms ? second_ms : first_ms;
  int fwd = first_ms < second_ms;
  struct hm_tent *arr;
  char *keep;
  uint64_t edge = 0;
  int n, i, step, taken = 0;

  *more = 0;
  if (limit < 1)
    limit = 1;
  arr = hm_tent_array(*list, &n);
  if (!arr) {
    *list = NULL;
    return 0;
  }
  qsort(arr, (size_t)n, sizeof(*arr), hm_tent_asc);
  keep = (char *)MyCalloc(1, (size_t)n);
  step = fwd ? 1 : -1;
  for (i = fwd ? 0 : n - 1; i >= 0 && i < n; i += step) {
    const struct hm_tent *e = &arr[i];
    if (e->ms <= lo || e->ms >= hi)
      continue;   /* outside the window: both bounds are exclusive */
    if (taken >= limit && e->ms != edge) {
      /* Past the page and its last group: is anything here to page on to? */
      if (!ok || ok(e->t, ctx)) {
        *more = 1;
        break;
      }
      continue;
    }
    if (ok && !ok(e->t, ctx))
      continue;
    keep[i] = 1;
    taken++;
    edge = e->ms;
  }
  *list = hm_tent_relink(arr, keep, n);
  MyFree(keep);
  MyFree(arr);
  return taken;
}

int hm_targets_responder(struct HistoryTarget **list, uint64_t first_ms, uint64_t second_ms,
                         int cap, int *cut)
{
  uint64_t lo = first_ms < second_ms ? first_ms : second_ms;
  uint64_t hi = first_ms < second_ms ? second_ms : first_ms;
  int fwd = first_ms < second_ms;
  struct hm_tent *arr, *in, *veto;
  struct HistoryTarget *head = NULL, **tail = &head;
  uint64_t edge = 0;
  int n, i, nin = 0, nveto = 0, kept = 0;

  *cut = 0;
  if (cap < 1)
    cap = 1;
  arr = hm_tent_array(*list, &n);
  if (!arr) {
    *list = NULL;
    return 0;
  }
  in = (struct hm_tent *)MyMalloc(sizeof(*in) * (size_t)n);
  veto = (struct hm_tent *)MyMalloc(sizeof(*veto) * (size_t)n);
  for (i = 0; i < n; i++) {
    if (arr[i].ms <= lo) {
      MyFree(arr[i].t);          /* no use to the requester: below the window */
    } else if (arr[i].ms < hi)
      in[nin++] = arr[i];
    else
      veto[nveto++] = arr[i];
  }
  qsort(in, (size_t)nin, sizeof(*in), fwd ? hm_tent_asc : hm_tent_desc);
  qsort(veto, (size_t)nveto, sizeof(*veto), hm_tent_asc);
  for (i = 0; i < nin; i++) {
    /* Past the cap only to finish the last kept group of equal stamps. */
    if (kept >= cap && (*cut || in[i].ms != edge)) {
      *cut = 1;
      MyFree(in[i].t);
      continue;
    }
    *tail = in[i].t;
    tail = &in[i].t->next;
    kept++;
    edge = in[i].ms;
  }
  for (i = 0; i < nveto; i++) {
    if (kept >= cap) {
      *cut = 1;
      MyFree(veto[i].t);
      continue;
    }
    *tail = veto[i].t;
    tail = &veto[i].t->next;
    kept++;
  }
  *tail = NULL;
  *list = head;
  MyFree(in);
  MyFree(veto);
  MyFree(arr);
  return kept;
}

void hm_targets_resp_row(struct hm_targets_resp *r, uint64_t first_ms,
                         uint64_t second_ms, uint64_t ms)
{
  uint64_t lo = first_ms < second_ms ? first_ms : second_ms;
  uint64_t hi = first_ms < second_ms ? second_ms : first_ms;

  if (ms > lo && ms < hi) {
    r->any_in = 1;
    r->last_in_ms = ms;
  } else if (ms >= hi)
    r->saw_veto = 1;
}

int hm_targets_cut_partial(const struct hm_targets_resp *resp, int n,
                           uint64_t first_ms, uint64_t second_ms,
                           const struct HistoryTarget *page, int more)
{
  int fwd = first_ms < second_ms, has = 0, i;
  uint64_t horizon = 0;
  const struct HistoryTarget *t;

  for (i = 0; i < n; i++) {
    uint64_t h;
    if (!resp[i].cut || resp[i].saw_veto)
      continue;
    h = resp[i].any_in ? resp[i].last_in_ms : first_ms;
    if (!has || (fwd ? h < horizon : h > horizon))
      horizon = h;
    has = 1;
  }
  if (!has)
    return 0;
  /* A page that claims the rest of the window (nothing eligible beyond
   * it) claims what lies past the horizon too: a hole (review of
   * 28cc0b18).  A full page with more beyond is whole up to its edge when
   * the edge is inside the horizon; the next page asks again from there. */
  if (!more)
    return 1;
  for (t = page; t; t = t->next) {
    uint64_t ms = hm_ts_ms(t->last_timestamp);
    if (fwd ? ms > horizon : ms < horizon)
      return 1;
  }
  return 0;
}
