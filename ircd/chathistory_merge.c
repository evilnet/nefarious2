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
 * hm_parse_ids).
 */
#include "config.h"

#include "chathistory_merge.h"
#include "history.h"
#include "ircd_alloc.h"
#include "ircd_string.h"

#include <stdlib.h>
#include <string.h>

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
