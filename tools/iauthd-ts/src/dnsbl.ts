/**
 * DNSBL lookup module with caching
 */

import { promises as dns } from 'node:dns';
import type { CacheEntry, DNSBLAnswer, DNSBLConfig } from './types.js';

/** Global DNSBL result cache: definite answers only */
const cache = new Map<string, CacheEntry>();

/** Lookups in flight, by query: a later asker shares the same lookup.
 * ttl: the longest cache time among the askers -- what the answer is
 * stored for (0: not stored). */
const inflight = new Map<string, { answer: Promise<DNSBLAnswer>; ttl: number }>();

/**
 * Expired entries are swept out on insert, once the inserts since the last
 * sweep reach the size the cache had after it (at least SWEEP_MIN): the
 * cost per insert stays constant, and the cache never holds more than twice
 * its size after the last sweep (the answers stored within the longest
 * cache time) plus SWEEP_MIN.
 */
const SWEEP_MIN = 256;
let insertsSinceSweep = 0;
let sizeAfterSweep = 0;

/**
 * Reverse an IPv4 address for DNSBL lookup
 * e.g., "192.168.1.10" -> "10.1.168.192"
 */
export function reverseIPv4(ip: string): string | null {
  const match = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return null;

  // Validate each octet is 0-255
  const octets = [match[1], match[2], match[3], match[4]].map(o => parseInt(o, 10));
  if (octets.some(o => o > 255)) return null;

  return `${match[4]}.${match[3]}.${match[2]}.${match[1]}`;
}

/**
 * Check if an IP is IPv4
 */
export function isIPv4(ip: string): boolean {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip);
}

/** Has \a entry outlived \a seconds? (<= 0: always) */
function olderThan(entry: CacheEntry, seconds: number, now: number): boolean {
  return seconds <= 0 || entry.ts <= now - seconds * 1000;
}

/**
 * Get cache entry if valid for a reader whose cache time is \a cacheTime
 * (and the entry has not outlived the cache time it was stored for)
 */
export function getCacheEntry(query: string, cacheTime: number): CacheEntry | null {
  const entry = cache.get(query);
  if (!entry) return null;

  const now = Date.now();
  if (olderThan(entry, entry.ttl, now)) {
    // Expired for everybody
    cache.delete(query);
    return null;
  }
  if (olderThan(entry, cacheTime, now)) {
    // Too old for this reader (cachetime=0, or shorter than another line
    // naming the same list): it may still serve the others
    return null;
  }

  return entry;
}

/**
 * Set cache entry, kept for \a ttl seconds (<= 0: not stored)
 */
export function setCacheEntry(query: string, result: string[], ttl: number): void {
  if (!(ttl > 0)) return;
  cache.set(query, {
    result,
    ts: Date.now(),
    ttl,
  });
  if (++insertsSinceSweep >= Math.max(SWEEP_MIN, sizeAfterSweep)) {
    sweepCache();
  }
}

/**
 * Remove every entry that has outlived the cache time it was stored for.
 * Returns how many were removed.
 */
export function sweepCache(): number {
  const now = Date.now();
  let removed = 0;
  for (const [query, entry] of cache) {
    if (olderThan(entry, entry.ttl, now)) {
      cache.delete(query);
      removed++;
    }
  }
  insertsSinceSweep = 0;
  sizeAfterSweep = cache.size;
  return removed;
}

/**
 * Get cache size for stats
 */
export function getCacheSize(): number {
  return cache.size;
}

/**
 * Error codes from dns.resolve4 that are a definite "not listed": the list's
 * server answered NXDOMAIN (ENOTFOUND) or NODATA (ENODATA).  Every other
 * failure -- SERVFAIL (ESERVFAIL), REFUSED (EREFUSED), the resolver's own
 * timeout (ETIMEOUT), an unreachable server (ECONNREFUSED), our DNSTIMEOUT --
 * says nothing about the address.
 */
const NOT_LISTED_CODES = new Set(['ENOTFOUND', 'ENODATA']);

/**
 * Perform a DNSBL lookup
 * Returns the result IPs ([] if not listed).  definite is false when the
 * lookup failed or timed out: the address then counts as not listed for the
 * client at hand, but the answer must not be cached.
 */
export async function lookupDNSBL(
  reversedIp: string,
  dnsblServer: string,
  timeout: number
): Promise<DNSBLAnswer> {
  const query = `${reversedIp}.${dnsblServer}`;
  let timer: NodeJS.Timeout | undefined;

  try {
    // Race against timeout
    const timeoutPromise = new Promise<string[]>((_, reject) => {
      timer = setTimeout(() => reject(new Error('DNS timeout')), timeout * 1000);
    });

    const lookupPromise = dns.resolve4(query);
    const results = await Promise.race([lookupPromise, timeoutPromise]);

    return { results, definite: true };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code && NOT_LISTED_CODES.has(code)) {
      return { results: [], definite: true };
    }
    const message = err instanceof Error ? err.message : String(err);
    return { results: [], definite: false, error: code ?? message };
  } finally {
    clearTimeout(timer);
  }
}

/** Where queryDNSBL's answer comes from */
export type DNSBLAnswerSource = 'cache' | 'shared' | 'lookup';

/**
 * Answer a DNSBL query from the cache, from the lookup of the same query
 * already in flight, or from a new lookup.  A definite answer is cached when
 * the lookup ends; a failed one is not, and every client that waited on it
 * gets the same "not listed, not definite" answer.  A waiter never waits
 * longer than the lookup it shares, which gives up after \a timeout seconds.
 */
export function queryDNSBL(
  reversedIp: string,
  dnsblServer: string,
  timeout: number,
  cacheTime: number
): { source: DNSBLAnswerSource; answer: Promise<DNSBLAnswer> } {
  const query = `${reversedIp}.${dnsblServer}`;

  const cached = getCacheEntry(query, cacheTime);
  if (cached) {
    return { source: 'cache', answer: Promise.resolve({ results: cached.result, definite: true }) };
  }

  const pending = inflight.get(query);
  if (pending) {
    pending.ttl = Math.max(pending.ttl, cacheTime);
    return { source: 'shared', answer: pending.answer };
  }

  const answer = lookupDNSBL(reversedIp, dnsblServer, timeout)
    .catch((err): DNSBLAnswer => ({ results: [], definite: false, error: String(err) }))
    .then((result) => {
      // Before any waiter sees the answer: the lookup is over, and a
      // definite answer is in the cache for the next asker.
      inflight.delete(query);
      if (result.definite) {
        setCacheEntry(query, result.results, record.ttl);
      }
      return result;
    });
  const record = { answer, ttl: cacheTime };
  inflight.set(query, record);
  return { source: 'lookup', answer };
}

/**
 * Check if a DNSBL result matches the configuration
 */
export function matchesDNSBL(results: string[], config: DNSBLConfig): boolean {
  for (const ip of results) {
    const match = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!match) continue;

    const value = parseInt(match[4], 10);

    // Check index match
    if (config.index) {
      const indices = config.index.split(',').map(i => parseInt(i.trim(), 10));
      if (indices.includes(value)) {
        return true;
      }
    }

    // Check bitmask match
    if (config.bitmask) {
      const bitmasks = config.bitmask.split(',').map(b => parseInt(b.trim(), 10));
      for (const bitmask of bitmasks) {
        if ((bitmask & value) !== 0) {
          return true;
        }
      }
    }

    // If no index or bitmask specified, any result is a match
    if (!config.index && !config.bitmask) {
      return true;
    }
  }

  return false;
}

/**
 * Parse DNSBL query to extract IP and server
 */
export function parseQuery(query: string): { ip: string; server: string } | null {
  const match = query.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(.+)$/);
  if (!match) return null;

  return {
    ip: `${match[4]}.${match[3]}.${match[2]}.${match[1]}`,
    server: match[5],
  };
}
