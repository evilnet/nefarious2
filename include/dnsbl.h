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
  char *index;               /**< Comma-separated indexes as written (e.g., "2,3,5,6"), or NULL */
  unsigned char index_set[32]; /**< The reply values (0-255) the index lists, one bit each */
  char *conn_class;          /**< class=: the connection class a matched,
                                  staying client is given, or NULL */
  int order;                 /**< Its place in the configuration (file order) */
  int has_cachetime;         /**< cachetime was given */
  unsigned int cachetime;    /**< How long its answers are cached (seconds;
                                  else FEAT_DNSBL_CACHETIME; 0: not cached) */
  int has_bitmask;           /**< A bitmask was given (bitmask = 0 matches nothing) */
  unsigned int bitmask;      /**< Matches a reply value v when v & bitmask */
  unsigned long long ident;  /**< The entry's name, kept across a rehash
                                  that does not change its block: a hash of
                                  domain, index text, bitmask and its place
                                  among the entries written alike (dnsbl.c) */
  enum DNSBLAction action;   /**< Action to take on match */
  char *mark;                /**< Mark string (for DNSBL_ACT_MARK) */
  int score;                 /**< Score value (for scoring mode) */
  /* Statistics */
  unsigned long queries;     /**< Total queries sent */
  unsigned long hits;        /**< Total positive hits */
  unsigned long blocks;      /**< Total blocks performed */
};

/** One DNSBL entry's answer about an address: what a lookup learned,
 * kept so that a verdict can be judged again by the entries in force
 * later.  The entry is named by its ident (no strings are copied). */
struct DNSBLAnswer {
  unsigned long long ident;      /**< The entry asked (DNSBLServer.ident) */
  int listed;                    /**< The address is listed there */
  unsigned char values[32];      /**< If so, the reply values (last octets
                                      of every A record), one bit each */
};

/** Structure for caching DNSBL lookup results: the answers, not a verdict
 * (dnsbl_cache_replay() judges them by the entries in force), under the
 * address that was asked about.  At most FEAT_DNSBL_CACHEMAX of them; the
 * oldest goes first. */
struct DNSBLCacheEntry {
  struct DNSBLCacheEntry *next;  /**< Hash table chain */
  struct DNSBLCacheEntry *older; /**< The age list (oldest first) */
  struct DNSBLCacheEntry *newer;
  struct irc_in_addr addr;       /**< The address the lookup asked about */
  time_t created;                /**< When the lookup answered */
  time_t expire;                 /**< When the longest-lived entry's answer
                                      expires (each entry's own: at replay) */
  struct DNSBLAnswer *answers;   /**< One per entry asked */
  int nanswers;                  /**< How many */
};

/** DNSBL lookup request tracking */
struct DNSBLRequest {
  struct Client *client;         /**< Associated client */
  struct DNSBLRequest *next;     /**< Next on the list of lookups in flight
                                      (dnsbl_timeout_sweep()) */
  int active;                    /**< On that list */
  time_t deadline;               /**< FEAT_DNSBL_TIMEOUT: given up then */
  int gave_up;                   /**< Given up: later answers are ignored */
  int pending_count;             /**< Number of pending lookups */
  unsigned int result;           /**< Answers that matched their entry */
  int whitelisted;               /**< Set if whitelist hit */
  int cancelled;                 /**< Set if request was cancelled (client disconnected) */
  enum DNSBLAction action;       /**< Highest priority action */
  char *mark;                    /**< Mark string to apply */
  char *conn_class;              /**< The class of the last matching entry
                                      (in file order) that gives one */
  int class_order;               /**< That entry's place */
  char **marks;                  /**< Every matching mark entry's mark (its reason) */
  int nmarks;                    /**< How many */
  struct irc_in_addr addr;       /**< The address asked about (the cache key) */
  struct DNSBLAnswer *answers;   /**< The answers so far (for the cache) */
  int nanswers;                  /**< How many */
  int unknown;                   /**< A lookup failed (timeout, SERVFAIL):
                                      its result is not cached */
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

/** The longest mark a DNSBL entry may give (MARK tags are single words;
 * they are shown in WHOIS and sent to every server and to services). */
#define DNSBL_MARKLEN 64

/* Function prototypes */

/** Initialize the DNSBL subsystem */
extern void dnsbl_init(void);

/** Add a DNSBL server configuration
 * @param domain DNSBL domain name
 * @param index Comma-separated reply values (0-255) to match exactly (or NULL)
 * @param bitmask A reply value v matches when v & *bitmask (NULL: no
 *   bitmask; a bitmask of 0 matches nothing).  With neither index nor
 *   bitmask, every answer matches; with both, either does (iauthd-ts).
 * @param action Action to take on match
 * @param mark Mark string (for DNSBL_ACT_MARK)
 * @param score Score value (for scoring mode)
 * @return Pointer to created server config, or NULL on error (no domain,
 *   or an index that is not a list of 0-255 values)
 */
extern struct DNSBLServer *dnsbl_add_server(const char *domain, const char *index,
                                            const unsigned int *bitmask, enum DNSBLAction action,
                                            const char *mark, int score);

/** Is \a mark usable as a DNSBL entry's mark: one word (no blanks), 1 to
 * DNSBL_MARKLEN characters? */
extern int dnsbl_valid_mark(const char *mark);

/** Give up the lookups in flight whose FEAT_DNSBL_TIMEOUT has passed: an
 * unanswered list counts as not listing the client, as one that fails
 * does, nothing of the lookup is cached, and the client goes on (run each
 * second from a timer; exported for the tests). */
extern void dnsbl_timeout_sweep(void);

/** Give an entry its own cache lifetime (the scripts' cachetime=): its
 * answers are used from the cache for that long instead of
 * FEAT_DNSBL_CACHETIME (0: never).
 * @param server The entry dnsbl_add_server() returned
 * @param seconds The lifetime
 */
extern void dnsbl_server_cachetime(struct DNSBLServer *server, unsigned int seconds);

/** Give an entry a connection class (the scripts' class=): a client it
 * matches, if it stays, is put in that class as IAuth's D line would.
 * @param server The entry dnsbl_add_server() returned
 * @param name The class name
 */
extern void dnsbl_server_class(struct DNSBLServer *server, const char *name);

/** The connection class a completed DNSBL check gives its client: the last
 * matching entry's (in file order) that has one, or NULL. */
extern const char *dnsbl_class(const struct DNSBLRequest *request);

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

/** Give a client that stays every mark its DNSBL check found: each
 * matching entry whose action is mark (as the iauthd scripts mark a
 * client they pass).
 * @param cptr The client
 * @param request Its completed DNSBL request
 */
extern void dnsbl_apply_marks(struct Client *cptr, const struct DNSBLRequest *request);

/** Take back the marks dnsbl_apply_marks() gave (the client's address
 * changed: the verdict was the old address's).
 * @param cptr The client
 * @param request The DNSBL request whose marks were applied
 */
extern void dnsbl_unapply_marks(struct Client *cptr, const struct DNSBLRequest *request);

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
