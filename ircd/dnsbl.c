/*
 * IRC - Internet Relay Chat, ircd/dnsbl.c
 * Copyright (C) 2025 Nefarious Development
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 * @brief Native DNSBL checking implementation.
 */
#include "config.h"

#include "dnsbl.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "res.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_stats.h"
#include "send.h"
#include "ircd_events.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/** Hash table size for DNSBL cache */
#define DNSBL_CACHE_SIZE 4096

/** Maximum DNSBL query hostname length */
#define DNSBL_QUERY_MAXLEN 512

/** Linked list of configured DNSBL servers */
static struct DNSBLServer *dnsbl_servers = NULL;

/** Hash table for DNSBL cache */
static struct DNSBLCacheEntry *dnsbl_cache[DNSBL_CACHE_SIZE];

/** Global DNSBL statistics */
static struct DNSBLStats dnsbl_stats;

/** Timer for cache expiration */
static struct Timer dnsbl_cache_timer;

/** Timer callback for cache expiration
 * @param ev Timer event
 */
static void
dnsbl_cache_timer_callback(struct Event *ev)
{
  if (ev_type(ev) == ET_EXPIRE)
    dnsbl_cache_expire();
}

/** Hash function for IP addresses */
static unsigned int
dnsbl_hash_addr(const struct irc_in_addr *addr)
{
  unsigned int hash = 0;
  int i;

  for (i = 0; i < 8; i++) {
    hash ^= addr->in6_16[i];
    hash = (hash << 5) | (hash >> 27);
  }

  return hash % DNSBL_CACHE_SIZE;
}

/** Compare two IP addresses for equality */
static int
dnsbl_addr_equal(const struct irc_in_addr *a, const struct irc_in_addr *b)
{
  return memcmp(a, b, sizeof(struct irc_in_addr)) == 0;
}

/** Parse an index: comma-separated reply values, each 0-255, as the
 * iauthd scripts take them (index=2,3,5,6).  Blanks around a value are
 * allowed.
 * @param[in] index The index as written.
 * @param[out] set One bit per value listed.
 * @return Zero, or -1 if \a index is not such a list (empty, a value out
 *   of range, anything else in it).
 */
static int
dnsbl_parse_index(const char *index, unsigned char set[32])
{
  const char *p = index;
  int n = 0;

  memset(set, 0, 32);
  for (;;) {
    long val = 0;
    int digits = 0;

    while (*p == ' ' || *p == '\t')
      p++;
    while (*p >= '0' && *p <= '9' && digits < 4) {
      val = val * 10 + (*p++ - '0');
      digits++;
    }
    while (*p == ' ' || *p == '\t')
      p++;
    if (!digits || val > 255 || (*p != ',' && *p != '\0'))
      return -1;
    set[val >> 3] |= (unsigned char)(1 << (val & 7));
    n++;
    if (*p == '\0')
      break;
    p++;                                  /* the comma */
  }
  return n ? 0 : -1;
}

/** Does reply value \a value match \a server?  As the iauthd scripts
 * decide (iauthd-ts matchesDNSBL()): the index lists it, or it shares a
 * bit with the bitmask; an entry with neither matches every answer.
 * @param[in] server A configured entry.
 * @param[in] value An answer's last octet.
 */
static int
dnsbl_entry_matches(const struct DNSBLServer *server, unsigned int value)
{
  if (!server->index && !server->bitmask)
    return 1;
  if (server->index && (server->index_set[value >> 3] & (1 << (value & 7))))
    return 1;
  return (server->bitmask & value) != 0;
}

void
dnsbl_init(void)
{
  memset(dnsbl_cache, 0, sizeof(dnsbl_cache));
  memset(&dnsbl_stats, 0, sizeof(dnsbl_stats));

  /* Set up cache expiration timer - run every 5 minutes */
  timer_add(timer_init(&dnsbl_cache_timer), dnsbl_cache_timer_callback,
            NULL, TT_PERIODIC, 300);
}

int
dnsbl_valid_mark(const char *mark)
{
  size_t len = mark ? strlen(mark) : 0;

  return len > 0 && len <= DNSBL_MARKLEN && !strpbrk(mark, " \t,");
}

struct DNSBLServer *
dnsbl_add_server(const char *domain, const char *index,
                 unsigned int bitmask, enum DNSBLAction action,
                 const char *mark, int score)
{
  struct DNSBLServer *server;

  if (!domain || !*domain)
    return NULL;

  server = (struct DNSBLServer *)MyCalloc(1, sizeof(struct DNSBLServer));
  if (!server)
    return NULL;

  if ((index && *index && dnsbl_parse_index(index, server->index_set))
      || (action == DNSBL_ACT_MARK && mark && *mark && !dnsbl_valid_mark(mark))) {
    MyFree(server);
    return NULL;                  /* the parser reports it */
  }

  DupString(server->domain, domain);
  if (index && *index)
    DupString(server->index, index);
  server->bitmask = bitmask;

  server->action = action;
  if (mark && *mark)
    DupString(server->mark, mark);
  server->score = score;

  /* Add to list */
  server->next = dnsbl_servers;
  dnsbl_servers = server;

  Debug((DEBUG_DNS, "DNSBL: Added server %s index=%s bitmask=0x%x action=%d",
         domain, server->index ? server->index : "-", server->bitmask, action));

  return server;
}

void
dnsbl_clear_servers(void)
{
  struct DNSBLServer *server, *next;

  for (server = dnsbl_servers; server; server = next) {
    next = server->next;
    MyFree(server->domain);
    if (server->index)
      MyFree(server->index);
    if (server->mark)
      MyFree(server->mark);
    MyFree(server);
  }
  dnsbl_servers = NULL;
}

void
dnsbl_format_ipv4(unsigned int addr, const char *domain, char *buf, size_t buflen)
{
  /* Reverse the octets and append the domain */
  ircd_snprintf(NULL, buf, buflen, "%u.%u.%u.%u.%s",
                (addr & 0xFF),
                (addr >> 8) & 0xFF,
                (addr >> 16) & 0xFF,
                (addr >> 24) & 0xFF,
                domain);
}

void
dnsbl_format_ipv6(const struct irc_in_addr *addr, const char *domain,
                  char *buf, size_t buflen)
{
  char *p = buf;
  int i;
  size_t remaining = buflen;
  int written;

  /* RFC 5782: Nibble-reverse the IPv6 address
   * For 2001:db8::1, this becomes:
   * 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.domain
   *
   * We iterate from the last 16-bit word to the first,
   * outputting each nibble in reverse order within each word.
   */
  for (i = 7; i >= 0; i--) {
    unsigned short word = ntohs(addr->in6_16[i]);
    written = ircd_snprintf(NULL, p, remaining, "%x.%x.%x.%x.",
                            (word >> 0) & 0xF,
                            (word >> 4) & 0xF,
                            (word >> 8) & 0xF,
                            (word >> 12) & 0xF);
    if (written < 0 || (size_t)written >= remaining)
      return;
    p += written;
    remaining -= written;
  }

  /* Append the domain */
  ircd_snprintf(NULL, p, remaining, "%s", domain);
}

/** Look up a cached DNSBL result */
static struct DNSBLCacheEntry *
dnsbl_cache_lookup(const struct irc_in_addr *addr)
{
  unsigned int hash = dnsbl_hash_addr(addr);
  struct DNSBLCacheEntry *entry;
  time_t now = CurrentTime;

  for (entry = dnsbl_cache[hash]; entry; entry = entry->next) {
    if (dnsbl_addr_equal(&entry->addr, addr)) {
      if (entry->expire > now) {
        dnsbl_stats.cache_hits++;
        return entry;
      }
      /* Entry expired - will be cleaned up later */
      break;
    }
  }

  dnsbl_stats.cache_misses++;
  return NULL;
}

/** Free a list of answers. */
static void
dnsbl_answers_free(struct DNSBLAnswer *answers, int n)
{
  int i;

  for (i = 0; i < n; i++) {
    MyFree(answers[i].domain);
    MyFree(answers[i].index);
  }
  MyFree(answers);
}

/** Free a cache entry. */
static void
dnsbl_cache_entry_free(struct DNSBLCacheEntry *entry)
{
  dnsbl_answers_free(entry->answers, entry->nanswers);
  MyFree(entry);
  dnsbl_stats.cache_size--;
}

/** Add a lookup's answers to the DNSBL cache, under the address the
 * lookup asked about; the cache takes the answers over. */
static void
dnsbl_cache_add(const struct irc_in_addr *addr, struct DNSBLAnswer *answers,
                int nanswers)
{
  unsigned int hash = dnsbl_hash_addr(addr);
  struct DNSBLCacheEntry *entry;

  entry = (struct DNSBLCacheEntry *)MyCalloc(1, sizeof(struct DNSBLCacheEntry));
  if (!entry) {
    dnsbl_answers_free(answers, nanswers);
    return;
  }

  memcpy(&entry->addr, addr, sizeof(struct irc_in_addr));
  entry->expire = CurrentTime + feature_int(FEAT_DNSBL_CACHETIME);
  entry->answers = answers;
  entry->nanswers = nanswers;

  entry->next = dnsbl_cache[hash];
  dnsbl_cache[hash] = entry;
  dnsbl_stats.cache_size++;
}

/** Drop \a stale from the cache (a newer lookup replaces it). */
static void
dnsbl_cache_drop(struct DNSBLCacheEntry *stale)
{
  struct DNSBLCacheEntry **pp;

  for (pp = &dnsbl_cache[dnsbl_hash_addr(&stale->addr)]; *pp; pp = &(*pp)->next)
    if (*pp == stale) {
      *pp = stale->next;
      dnsbl_cache_entry_free(stale);
      return;
    }
}

void
dnsbl_cache_expire(void)
{
  int i;
  struct DNSBLCacheEntry *entry, *prev, *next;
  time_t now = CurrentTime;

  for (i = 0; i < DNSBL_CACHE_SIZE; i++) {
    prev = NULL;
    for (entry = dnsbl_cache[i]; entry; entry = next) {
      next = entry->next;
      if (entry->expire <= now) {
        /* Remove expired entry */
        if (prev)
          prev->next = next;
        else
          dnsbl_cache[i] = next;
        dnsbl_cache_entry_free(entry);
      } else {
        prev = entry;
      }
    }
  }
}

/** Per-query context for DNSBL DNS lookups
 * Each DNS query gets its own context to avoid race conditions
 * with the server pointer being overwritten.
 *
 * It names the DNSBL entry the query was made for, never points at it: a
 * rehash during the lookup frees every entry (dnsbl_clear_servers()), and
 * the answer is judged by the entry the configuration in force when it
 * arrives has under that name (dnsbl_live_server()).  The name is the
 * entry's block as written -- domain, index text, reply values -- and,
 * as several blocks can be written alike (or differ only in an index the
 * parser drops: "250" and "251" both match every value), its place among
 * those alike.
 */
struct DNSBLQueryContext {
  struct DNSBLRequest *request;  /**< Parent request */
  char *domain;                  /**< The entry's domain */
  char *index;                   /**< Its index as written (NULL: none) */
  unsigned int bitmask;          /**< The reply values it matched */
  int nth;                       /**< Its place among the entries alike */
};

/** Is \a server the entry written as \a domain, \a index, \a bitmask? */
static int
dnsbl_entry_is(const struct DNSBLServer *server, const char *domain,
               const char *index, unsigned int bitmask)
{
  return server->bitmask == bitmask
    && !ircd_strcmp(server->domain, domain)
    && ((!server->index && !index)
        || (server->index && index && !strcmp(server->index, index)));
}

/** \a server's place among the configured entries written alike. */
static int
dnsbl_entry_nth(const struct DNSBLServer *server)
{
  const struct DNSBLServer *s;
  int nth = 0;

  for (s = dnsbl_servers; s && s != server; s = s->next)
    if (dnsbl_entry_is(s, server->domain, server->index, server->bitmask))
      nth++;
  return nth;
}

/** The entry an answer is judged by: the configured entry written as the
 * query's was (domain, index text, reply values), at the same place among
 * those alike.  None (the rehash removed or changed it) means the answer
 * is ignored.  Action and mark are the live entry's.
 * @return The live entry, or NULL.
 */
static struct DNSBLServer *
dnsbl_live_server(const struct DNSBLQueryContext *ctx)
{
  struct DNSBLServer *server;
  int nth = 0;

  for (server = dnsbl_servers; server; server = server->next)
    if (dnsbl_entry_is(server, ctx->domain, ctx->index, ctx->bitmask)
        && nth++ == ctx->nth)
      return server;
  return NULL;
}

/** Free a DNSBL request and all its resources */
static void
dnsbl_request_free(struct DNSBLRequest *req)
{
  int i;

  if (!req)
    return;

  if (req->mark)
    MyFree(req->mark);
  for (i = 0; i < req->nmarks; i++)
    MyFree(req->marks[i]);        /* (a macro: no side effects in its argument) */
  MyFree(req->marks);
  dnsbl_answers_free(req->answers, req->nanswers);
  MyFree(req);
}

/** Keep \a mark for the client of \a req (once). */
static void
dnsbl_note_mark(struct DNSBLRequest *req, const char *mark)
{
  int i;

  for (i = 0; i < req->nmarks; i++)
    if (!strcmp(req->marks[i], mark))
      return;
  req->marks = (char **)MyRealloc(req->marks, (req->nmarks + 1) * sizeof(char *));
  DupString(req->marks[req->nmarks], mark);
  req->nmarks++;
}

/** Judge one entry's answer for \a req: \a value is the reply value (the
 * answer's last octet); the entry's index or bitmask says whether it
 * counts (dnsbl_entry_matches()), its action what it does. */
static void
dnsbl_judge(struct DNSBLRequest *req, struct DNSBLServer *server,
            unsigned int value)
{
  Debug((DEBUG_DNS, "DNSBL: Got response for %s, result byte=%u",
         server->domain, value));

  if (!dnsbl_entry_matches(server, value))
    return;
  server->hits++;
  req->result++;

  /* Every matching mark entry marks the client (if it stays), as the
   * scripts' marks{} (iauthd.pl, iauthd-ts) collect every mark= of the
   * lines that matched.  The reason of a block or whitelist entry is its
   * refusal text, no mark. */
  if (server->action == DNSBL_ACT_MARK && server->mark)
    dnsbl_note_mark(req, server->mark);

  /* Process the action based on priority */
  switch (server->action) {
  case DNSBL_ACT_WHITELIST:
    req->whitelisted = 1;
    dnsbl_stats.total_whitelists++;
    Debug((DEBUG_DNS, "DNSBL: Whitelist hit from %s", server->domain));
    break;

  case DNSBL_ACT_BLOCK_ALL:
    if (req->action < DNSBL_ACT_BLOCK_ALL && !req->whitelisted) {
      req->action = DNSBL_ACT_BLOCK_ALL;
      server->blocks++;
      dnsbl_stats.total_blocks++;
    }
    break;

  case DNSBL_ACT_BLOCK_ANON:
    if (req->action < DNSBL_ACT_BLOCK_ANON && !req->whitelisted) {
      req->action = DNSBL_ACT_BLOCK_ANON;
      server->blocks++;
    }
    break;

  case DNSBL_ACT_MARK:
    if (req->action < DNSBL_ACT_MARK && !req->whitelisted) {
      req->action = DNSBL_ACT_MARK;
      if (server->mark) {
        if (req->mark)
          MyFree(req->mark);
        DupString(req->mark, server->mark);
      }
      dnsbl_stats.total_marks++;
    }
    break;

  default:
    break;
  }
}

/** Keep \a server's answer on \a req, for the cache. */
static void
dnsbl_note_answer(struct DNSBLRequest *req, struct DNSBLServer *server,
                  int listed, const unsigned char values[32])
{
  struct DNSBLAnswer *a;

  req->answers = (struct DNSBLAnswer *)MyRealloc(req->answers,
                   (req->nanswers + 1) * sizeof(*req->answers));
  a = &req->answers[req->nanswers++];
  DupString(a->domain, server->domain);
  a->index = NULL;
  if (server->index)
    DupString(a->index, server->index);
  a->bitmask = server->bitmask;
  a->nth = dnsbl_entry_nth(server);
  a->listed = listed;
  memcpy(a->values, values, sizeof(a->values));
}

/** The answer \a cached holds for the configured entry \a server (same
 * name: domain, index text, bitmask, place among those alike), or NULL. */
static const struct DNSBLAnswer *
dnsbl_cached_answer(const struct DNSBLCacheEntry *cached,
                    const struct DNSBLServer *server)
{
  int nth = dnsbl_entry_nth(server);
  int i;

  for (i = 0; i < cached->nanswers; i++)
    if (cached->answers[i].nth == nth
        && dnsbl_entry_is(server, cached->answers[i].domain,
                          cached->answers[i].index, cached->answers[i].bitmask))
      return &cached->answers[i];
  return NULL;
}

/** A cached lookup's verdict, judged by the entries in force now: each
 * configured entry's cached answer, under that entry's index, bitmask,
 * action and mark (as the scripts judge their cached answers).  An entry
 * with no cached answer (added, or changed, since the lookup) makes the
 * cache entry stale: it is dropped, and NULL says to look up again.
 * Answers of entries removed since are ignored.
 * @return A completed request (nothing pending), or NULL.
 */
static struct DNSBLRequest *
dnsbl_cache_replay(struct Client *cptr, struct DNSBLCacheEntry *cached)
{
  struct DNSBLServer *server;
  struct DNSBLRequest *req;
  const struct DNSBLAnswer *a;

  for (server = dnsbl_servers; server; server = server->next)
    if (!dnsbl_cached_answer(cached, server)) {
      Debug((DEBUG_DNS, "DNSBL: Cached result stale (%s not asked)",
             server->domain));
      dnsbl_cache_drop(cached);
      return NULL;
    }

  req = (struct DNSBLRequest *)MyCalloc(1, sizeof(struct DNSBLRequest));
  req->client = cptr;
  req->action = DNSBL_ACT_NONE;
  memcpy(&req->addr, &cached->addr, sizeof(req->addr));
  for (server = dnsbl_servers; server; server = server->next)
    if ((a = dnsbl_cached_answer(cached, server)) && a->listed) {
      unsigned int v;

      for (v = 0; v < 256; v++)
        if (a->values[v >> 3] & (1 << (v & 7)))
          dnsbl_judge(req, server, v);
    }
  return req;
}

/** Callback for DNSBL DNS lookup completion */
static void
dnsbl_dns_callback(void *vptr, const struct irc_in_addr *addr, const char *h)
{
  struct DNSBLQueryContext *ctx = (struct DNSBLQueryContext *)vptr;
  struct DNSBLRequest *req;
  struct DNSBLServer *server;
  unsigned int result_byte = 0;
  unsigned char values[32];

  memset(values, 0, sizeof(values));
  if (!ctx) {
    return;
  }

  req = ctx->request;
  server = dnsbl_live_server(ctx);
  if (addr && !server)
    Debug((DEBUG_DNS, "DNSBL: Answer from %s ignored: no such entry since a rehash",
           ctx->domain));

  /* Free the per-query context */
  MyFree(ctx->domain);
  MyFree(ctx->index);
  MyFree(ctx);

  if (!req) {
    return;
  }

  req->pending_count--;

  /* Check if request was cancelled (client disconnected) */
  if (req->cancelled) {
    /* If this was the last pending query, free the request */
    if (req->pending_count == 0) {
      dnsbl_request_free(req);
    }
    return;
  }

  if (!req->client) {
    /* Client gone but not properly cancelled - clean up */
    if (req->pending_count == 0) {
      dnsbl_request_free(req);
    }
    return;
  }

  if (addr) {
    /* We got a response: every A record of it is a listing, its value the
     * record's last octet -- read as the address's last BYTE (network
     * byte order; the low half of in6_16[7] in host order is the third
     * octet on a little-endian host).  The scripts judge each record. */
    const struct irc_in_addr *all;
    int i, n = res_last_addrs(&all);

    if (n <= 0) {
      all = addr;
      n = 1;
    }
    for (i = 0; i < n; i++) {
      result_byte = ((const unsigned char *) &all[i])[sizeof(all[i]) - 1];
      values[result_byte >> 3] |= (unsigned char)(1 << (result_byte & 7));
    }
  }
  /* Only a definite answer is kept for the cache: an address (listed),
   * or a server's NXDOMAIN (not listed).  A failure -- a timeout, SERVFAIL,
   * an unusable reply -- says nothing about the address: the client is
   * judged without that entry as before (not listed), but nothing of this
   * lookup is cached, and the next connection asks again. */
  if (!addr && res_last_outcome() != RES_OUT_NXDOMAIN)
    req->unknown = 1;
  else if (server)
    dnsbl_note_answer(req, server, addr != NULL, values);
  if (addr && server) {
    unsigned int v;

    for (v = 0; v < 256; v++)
      if (values[v >> 3] & (1 << (v & 7)))
        dnsbl_judge(req, server, v);
  }

  /* Check if all lookups are complete */
  if (req->pending_count == 0) {
    /* Cache the answers (not the verdict: a later hit judges them by the
     * entries in force then), under the address that was asked about --
     * the client's may have changed since (WEBIRC, IAuth) -- all of them
     * definite, or nothing */
    if (!req->unknown) {
      dnsbl_cache_add(&req->addr, req->answers, req->nanswers);
      req->answers = NULL;
      req->nanswers = 0;
    }

    /* Signal auth to continue */
    if (cli_auth(req->client))
      auth_dnsbl_complete(cli_auth(req->client));
  }
}

int
dnsbl_check(struct Client *cptr, struct DNSBLRequest **request)
{
  struct DNSBLServer *server;
  struct DNSBLRequest *req;
  struct DNSBLCacheEntry *cached;
  struct DNSBLQueryContext *ctx;
  char query[DNSBL_QUERY_MAXLEN];
  int started = 0;

  if (!feature_bool(FEAT_NATIVE_DNSBL))
    return 0;

  if (!dnsbl_servers)
    return 0;

  if (!cptr)
    return 0;

  /* Check cache first: a hit gives a completed request, judged by the
   * entries in force now; nothing is pending (0), the verdict is the
   * request's (dnsbl_result()).  A stale entry is looked up again. */
  cached = dnsbl_cache_lookup(&cli_ip(cptr));
  if (cached && (req = dnsbl_cache_replay(cptr, cached))) {
    Debug((DEBUG_DNS, "DNSBL: Cache hit for client"));
    if (request)
      *request = req;
    else
      dnsbl_request_free(req);
    return 0;
  }

  /* Create request structure */
  req = (struct DNSBLRequest *)MyCalloc(1, sizeof(struct DNSBLRequest));
  if (!req)
    return 0;

  req->client = cptr;
  req->action = DNSBL_ACT_NONE;
  req->cancelled = 0;
  memcpy(&req->addr, &cli_ip(cptr), sizeof(req->addr));   /* asked about */

  /* Return the request to the caller */
  if (request)
    *request = req;

  /* Start lookups for each configured DNSBL */
  for (server = dnsbl_servers; server; server = server->next) {
    /* Create per-query context to avoid stale server pointer issue */
    ctx = (struct DNSBLQueryContext *)MyCalloc(1, sizeof(struct DNSBLQueryContext));
    if (!ctx)
      continue;

    ctx->request = req;
    DupString(ctx->domain, server->domain);
    if (server->index)
      DupString(ctx->index, server->index);
    ctx->bitmask = server->bitmask;
    ctx->nth = dnsbl_entry_nth(server);

    /* Format the query based on IP version */
    if (irc_in_addr_is_ipv4(&cli_ip(cptr))) {
      /* The high group is shifted as unsigned: ntohs() promotes to int,
       * and a group of 0x8000 or more shifted by 16 overflows it. */
      unsigned int ipv4 = ((unsigned int)ntohs(cli_ip(cptr).in6_16[6]) << 16) |
                          ntohs(cli_ip(cptr).in6_16[7]);
      dnsbl_format_ipv4(ipv4, server->domain, query, sizeof(query));
    } else {
      dnsbl_format_ipv6(&cli_ip(cptr), server->domain, query, sizeof(query));
    }

    Debug((DEBUG_DNS, "DNSBL: Starting lookup for %s", query));

    server->queries++;
    req->pending_count++;
    dnsbl_stats.total_lookups++;

    /* Start the DNS lookup with per-query context */
    gethost_byname_a(query, dnsbl_dns_callback, ctx);   /* A only, every record */
    started++;
  }

  /* If no queries started, clean up the request */
  if (started == 0) {
    MyFree(req);
    if (request)
      *request = NULL;
  }

  return started > 0 ? 1 : 0;
}

void
dnsbl_cancel(struct DNSBLRequest *request)
{
  if (!request)
    return;

  /* Mark request as cancelled - don't free it here!
   * The DNS callbacks will complete asynchronously and check the
   * cancelled flag. The last callback to complete will free the request.
   * This prevents use-after-free when a malicious/slow DNS server
   * delays responses until after the client disconnects.
   */
  request->cancelled = 1;
  request->client = NULL;

  /* If no queries are pending, we can free immediately */
  if (request->pending_count == 0) {
    dnsbl_request_free(request);
  }
  /* Otherwise, the last callback will free it */
}

int
dnsbl_complete(struct DNSBLRequest *request)
{
  if (!request)
    return 1; /* No DNSBL check in progress */

  return request->pending_count == 0;
}

int
dnsbl_result(struct Client *cptr, struct DNSBLRequest *request,
             enum DNSBLAction *action, const char **mark)
{
  /* The request holds the verdict, a fresh lookup's or a cached one's
   * (dnsbl_check()) */
  if (request) {
    if (action)
      *action = request->whitelisted ? DNSBL_ACT_WHITELIST : request->action;
    if (mark)
      *mark = request->mark;

    return request->action >= DNSBL_ACT_BLOCK_ANON && !request->whitelisted;
  }

  if (action)
    *action = DNSBL_ACT_NONE;
  if (mark)
    *mark = NULL;

  return 0;
}

void
dnsbl_apply_marks(struct Client *cptr, const struct DNSBLRequest *request)
{
  int i;

  if (!request || !request->nmarks)
    return;
  for (i = 0; i < request->nmarks; i++)
    add_mark(cptr, request->marks[i]);
  SetMarked(cptr);
}

void
dnsbl_unapply_marks(struct Client *cptr, const struct DNSBLRequest *request)
{
  struct SLink **pp, *lp;
  int i;

  if (!request || !request->nmarks)
    return;
  for (i = 0; i < request->nmarks; i++)
    for (pp = &cli_marks(cptr); *pp; pp = &(*pp)->next)
      if (!strcmp((*pp)->value.cp, request->marks[i])) {
        lp = *pp;
        *pp = lp->next;
        MyFree(lp->value.cp);
        free_link(lp);
        break;
      }
  if (!cli_marks(cptr))
    ClrFlag(cptr, FLAG_MARKED);
}

const struct DNSBLStats *
dnsbl_get_stats(void)
{
  return &dnsbl_stats;
}

struct DNSBLServer *
dnsbl_first_server(void)
{
  return dnsbl_servers;
}

void
dnsbl_report_stats(struct Client *to, const struct StatDesc *sd, char *param)
{
  struct DNSBLServer *server;

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "D :DNSBL Statistics");
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "D :  Enabled: %s",
             feature_bool(FEAT_NATIVE_DNSBL) ? "YES" : "NO");
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "D :  Cache size: %lu entries",
             dnsbl_stats.cache_size);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "D :  Cache hits: %lu, misses: %lu",
             dnsbl_stats.cache_hits, dnsbl_stats.cache_misses);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "D :  Total lookups: %lu",
             dnsbl_stats.total_lookups);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "D :  Total blocks: %lu, marks: %lu, whitelists: %lu",
             dnsbl_stats.total_blocks, dnsbl_stats.total_marks,
             dnsbl_stats.total_whitelists);

  /* Per-server stats */
  for (server = dnsbl_servers; server; server = server->next) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "D :  %s: %lu queries, %lu hits, %lu blocks",
               server->domain, server->queries, server->hits, server->blocks);
  }
}
