/*
 * IRC - Internet Relay Chat, include/dnsbl.h
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
 * @brief Native DNSBL checking support.
 */
#ifndef INCLUDED_dnsbl_h
#define INCLUDED_dnsbl_h

#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"
#endif
#ifndef INCLUDED_res_h
#include "res.h"
#endif

struct Client;
struct StatDesc;

/** DNSBL action types */
enum DNSBLAction {
  DNSBL_ACT_NONE,       /**< No action (for whitelists that didn't hit) */
  DNSBL_ACT_MARK,       /**< Mark the client with a string */
  DNSBL_ACT_BLOCK_ANON, /**< Block anonymous (non-authed) users */
  DNSBL_ACT_BLOCK_ALL,  /**< Block all users */
  DNSBL_ACT_WHITELIST   /**< Whitelist - exempt from other DNSBL blocks */
};

/** Structure representing a configured DNSBL server */
struct DNSBLServer {
  struct DNSBLServer *next;  /**< Linked list next */
  char *domain;              /**< DNSBL domain (e.g., "dnsbl.dronebl.org") */
  char *index;               /**< Comma-separated indexes (e.g., "2,3,5,6") */
  unsigned int bitmask;      /**< Bitmask of reply values to match (alternative to index) */
  enum DNSBLAction action;   /**< Action to take on match */
  char *mark;                /**< Mark string (for DNSBL_ACT_MARK) */
  int score;                 /**< Score value (for scoring mode) */
  /* Statistics */
  unsigned long queries;     /**< Total queries sent */
  unsigned long hits;        /**< Total positive hits */
  unsigned long blocks;      /**< Total blocks performed */
};

/** Structure for caching DNSBL lookup results */
struct DNSBLCacheEntry {
  struct DNSBLCacheEntry *next;  /**< Hash table chain */
  struct irc_in_addr addr;       /**< IP address */
  time_t expire;                 /**< Expiration timestamp */
  unsigned int result;           /**< Cached result bitmask */
  char *server;                  /**< Which DNSBL server */
  enum DNSBLAction action;       /**< Action determined */
  char *mark;                    /**< Mark string if applicable */
};

/** DNSBL lookup request tracking */
struct DNSBLRequest {
  struct Client *client;         /**< Associated client */
  struct DNSBLRequest *next;     /**< Next pending request */
  int pending_count;             /**< Number of pending lookups */
  unsigned int result;           /**< Accumulated result */
  int whitelisted;               /**< Set if whitelist hit */
  int cancelled;                 /**< Set if request was cancelled (client disconnected) */
  enum DNSBLAction action;       /**< Highest priority action */
  char *mark;                    /**< Mark string to apply */
};

/** Global DNSBL statistics */
struct DNSBLStats {
  unsigned long cache_size;      /**< Current cache entries */
  unsigned long cache_hits;      /**< Cache lookup hits */
  unsigned long cache_misses;    /**< Cache lookup misses */
  unsigned long total_lookups;   /**< Total DNSBL lookups started */
  unsigned long total_blocks;    /**< Total clients blocked */
  unsigned long total_marks;     /**< Total clients marked */
  unsigned long total_whitelists;/**< Total whitelist hits */
};

/* Function prototypes */

/** Initialize the DNSBL subsystem */
extern void dnsbl_init(void);

/** Add a DNSBL server configuration
 * @param domain DNSBL domain name
 * @param index Comma-separated reply indexes to match (or NULL)
 * @param bitmask Bitmask of reply values (alternative to index)
 * @param action Action to take on match
 * @param mark Mark string (for DNSBL_ACT_MARK)
 * @param score Score value (for scoring mode)
 * @return Pointer to created server config, or NULL on error
 */
extern struct DNSBLServer *dnsbl_add_server(const char *domain, const char *index,
                                            unsigned int bitmask, enum DNSBLAction action,
                                            const char *mark, int score);

/** Remove all DNSBL server configurations */
extern void dnsbl_clear_servers(void);

/** Start DNSBL check for a client
 * @param cptr Client to check
 * @param request Pointer to store the DNSBL request
 * @return 1 if check started, 0 if no DNSBLs configured or disabled
 */
extern int dnsbl_check(struct Client *cptr, struct DNSBLRequest **request);

/** Cancel any pending DNSBL lookups for a client
 * @param request DNSBL request to cancel
 */
extern void dnsbl_cancel(struct DNSBLRequest *request);

/** Check if DNSBL lookups are complete
 * @param request DNSBL request to check
 * @return 1 if complete (or none pending), 0 if still waiting
 */
extern int dnsbl_complete(struct DNSBLRequest *request);

/** Get the result of DNSBL checks
 * @param cptr Client to get result for
 * @param request DNSBL request
 * @param[out] action Pointer to store action
 * @param[out] mark Pointer to store mark string (may be NULL)
 * @return 1 if blocked, 0 if allowed
 */
extern int dnsbl_result(struct Client *cptr, struct DNSBLRequest *request,
                        enum DNSBLAction *action, const char **mark);

/** Format an IPv4 address for DNSBL lookup
 * @param addr IPv4 address (last 32 bits of irc_in_addr)
 * @param domain DNSBL domain
 * @param buf Output buffer
 * @param buflen Size of output buffer
 */
extern void dnsbl_format_ipv4(unsigned int addr, const char *domain, char *buf, size_t buflen);

/** Format an IPv6 address for DNSBL lookup (RFC 5782 nibble format)
 * @param addr IPv6 address
 * @param domain DNSBL domain
 * @param buf Output buffer
 * @param buflen Size of output buffer
 */
extern void dnsbl_format_ipv6(const struct irc_in_addr *addr, const char *domain,
                              char *buf, size_t buflen);

/** Expire old cache entries */
extern void dnsbl_cache_expire(void);

/** Get DNSBL statistics */
extern const struct DNSBLStats *dnsbl_get_stats(void);

/** Report DNSBL statistics for /STATS D
 * @param to Client requesting stats
 * @param sd Stats descriptor
 * @param param Extra parameter (unused)
 */
extern void dnsbl_report_stats(struct Client *to, const struct StatDesc *sd, char *param);

/** Get first DNSBL server (for iteration) */
extern struct DNSBLServer *dnsbl_first_server(void);

#endif /* INCLUDED_dnsbl_h */
