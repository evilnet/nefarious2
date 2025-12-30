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
#include "msg.h"
#include "numeric.h"
#include "res.h"
#include "s_auth.h"
#include "s_bsd.h"
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

/** Parse a comma-separated index string into a bitmask
 * @param index String like "2,3,5,6"
 * @return Bitmask of indexes
 */
static unsigned int
dnsbl_parse_index(const char *index)
{
  unsigned int mask = 0;
  const char *p = index;
  char *endp;
  long val;

  if (!index || !*index)
    return 0xFFFFFFFF; /* match all by default */

  while (*p) {
    while (*p && (isspace((unsigned char)*p) || *p == ','))
      p++;
    if (!*p)
      break;

    val = strtol(p, &endp, 10);
    if (val >= 0 && val < 32)
      mask |= (1 << val);

    p = endp;
  }

  return mask ? mask : 0xFFFFFFFF;
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

  DupString(server->domain, domain);

  if (index && *index) {
    DupString(server->index, index);
    server->bitmask = dnsbl_parse_index(index);
  } else if (bitmask) {
    server->bitmask = bitmask;
  } else {
    server->bitmask = 0xFFFFFFFF; /* match all */
  }

  server->action = action;
  if (mark && *mark)
    DupString(server->mark, mark);
  server->score = score;

  /* Add to list */
  server->next = dnsbl_servers;
  dnsbl_servers = server;

  Debug((DEBUG_DNS, "DNSBL: Added server %s action=%d bitmask=0x%x",
         domain, action, server->bitmask));

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
    unsigned short word = addr->in6_16[i];
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

/** Add a result to the DNSBL cache */
static void
dnsbl_cache_add(const struct irc_in_addr *addr, const char *server,
                unsigned int result, enum DNSBLAction action, const char *mark)
{
  unsigned int hash = dnsbl_hash_addr(addr);
  struct DNSBLCacheEntry *entry;

  entry = (struct DNSBLCacheEntry *)MyCalloc(1, sizeof(struct DNSBLCacheEntry));
  if (!entry)
    return;

  memcpy(&entry->addr, addr, sizeof(struct irc_in_addr));
  entry->expire = CurrentTime + feature_int(FEAT_DNSBL_CACHETIME);
  entry->result = result;
  entry->action = action;
  if (server)
    DupString(entry->server, server);
  if (mark)
    DupString(entry->mark, mark);

  entry->next = dnsbl_cache[hash];
  dnsbl_cache[hash] = entry;
  dnsbl_stats.cache_size++;
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

        if (entry->server)
          MyFree(entry->server);
        if (entry->mark)
          MyFree(entry->mark);
        MyFree(entry);
        dnsbl_stats.cache_size--;
      } else {
        prev = entry;
      }
    }
  }
}

/** Callback for DNSBL DNS lookup completion */
static void
dnsbl_dns_callback(void *vptr, const struct irc_in_addr *addr, const char *h)
{
  struct DNSBLRequest *req = (struct DNSBLRequest *)vptr;
  unsigned int result_byte;

  if (!req || !req->client)
    return;

  req->pending_count--;

  if (addr) {
    /* We got a response - extract the last octet as the result */
    if (irc_in_addr_is_ipv4(addr)) {
      result_byte = addr->in6_16[7] & 0xFF;
    } else {
      result_byte = addr->in6_16[7] & 0xFF;
    }

    Debug((DEBUG_DNS, "DNSBL: Got response for %s, result byte=%u, bitmask=0x%x",
           req->server->domain, result_byte, req->server->bitmask));

    /* Check if this result matches our bitmask */
    if (req->server->bitmask & (1 << result_byte)) {
      req->server->hits++;
      req->result |= (1 << result_byte);

      /* Process the action based on priority */
      switch (req->server->action) {
      case DNSBL_ACT_WHITELIST:
        req->whitelisted = 1;
        dnsbl_stats.total_whitelists++;
        Debug((DEBUG_DNS, "DNSBL: Whitelist hit from %s", req->server->domain));
        break;

      case DNSBL_ACT_BLOCK_ALL:
        if (req->action < DNSBL_ACT_BLOCK_ALL && !req->whitelisted) {
          req->action = DNSBL_ACT_BLOCK_ALL;
          req->server->blocks++;
          dnsbl_stats.total_blocks++;
        }
        break;

      case DNSBL_ACT_BLOCK_ANON:
        if (req->action < DNSBL_ACT_BLOCK_ANON && !req->whitelisted) {
          req->action = DNSBL_ACT_BLOCK_ANON;
          req->server->blocks++;
        }
        break;

      case DNSBL_ACT_MARK:
        if (req->action < DNSBL_ACT_MARK && !req->whitelisted) {
          req->action = DNSBL_ACT_MARK;
          if (req->server->mark) {
            if (req->mark)
              MyFree(req->mark);
            DupString(req->mark, req->server->mark);
          }
          dnsbl_stats.total_marks++;
        }
        break;

      default:
        break;
      }
    }
  }

  /* Check if all lookups are complete */
  if (req->pending_count == 0) {
    /* Cache the result */
    dnsbl_cache_add(&cli_ip(req->client), NULL, req->result, req->action, req->mark);

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
  char query[DNSBL_QUERY_MAXLEN];
  int started = 0;

  if (!feature_bool(FEAT_NATIVE_DNSBL))
    return 0;

  if (!dnsbl_servers)
    return 0;

  if (!cptr)
    return 0;

  /* Check cache first */
  cached = dnsbl_cache_lookup(&cli_ip(cptr));
  if (cached) {
    /* Use cached result */
    Debug((DEBUG_DNS, "DNSBL: Cache hit for client"));
    return 0; /* Already have result, no lookup needed */
  }

  /* Create request structure */
  req = (struct DNSBLRequest *)MyCalloc(1, sizeof(struct DNSBLRequest));
  if (!req)
    return 0;

  req->client = cptr;
  req->action = DNSBL_ACT_NONE;

  /* Return the request to the caller */
  if (request)
    *request = req;

  /* Start lookups for each configured DNSBL */
  for (server = dnsbl_servers; server; server = server->next) {
    req->server = server;

    /* Format the query based on IP version */
    if (irc_in_addr_is_ipv4(&cli_ip(cptr))) {
      unsigned int ipv4 = (cli_ip(cptr).in6_16[6] << 16) |
                          cli_ip(cptr).in6_16[7];
      dnsbl_format_ipv4(ipv4, server->domain, query, sizeof(query));
    } else {
      dnsbl_format_ipv6(&cli_ip(cptr), server->domain, query, sizeof(query));
    }

    Debug((DEBUG_DNS, "DNSBL: Starting lookup for %s", query));

    server->queries++;
    req->pending_count++;
    dnsbl_stats.total_lookups++;

    /* Start the DNS lookup */
    gethost_byname(query, dnsbl_dns_callback, req);
    started++;
  }

  return started > 0 ? 1 : 0;
}

void
dnsbl_cancel(struct DNSBLRequest *request)
{
  if (!request)
    return;

  /* Note: DNS requests will complete on their own, but we disconnect
   * the client reference so callbacks become no-ops */
  request->client = NULL;

  if (request->mark)
    MyFree(request->mark);
  MyFree(request);
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
  struct DNSBLCacheEntry *cached;

  /* Check if we have a pending request with results */
  if (request) {
    if (action)
      *action = request->whitelisted ? DNSBL_ACT_WHITELIST : request->action;
    if (mark)
      *mark = request->mark;

    return request->action >= DNSBL_ACT_BLOCK_ANON && !request->whitelisted;
  }

  /* Check cache */
  if (cptr) {
    cached = dnsbl_cache_lookup(&cli_ip(cptr));
    if (cached) {
      if (action)
        *action = cached->action;
      if (mark)
        *mark = cached->mark;

      return cached->action >= DNSBL_ACT_BLOCK_ANON;
    }
  }

  if (action)
    *action = DNSBL_ACT_NONE;
  if (mark)
    *mark = NULL;

  return 0;
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
