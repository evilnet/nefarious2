/**
 * DNSBL lookup module with caching
 */

import { promises as dns } from 'node:dns';
import type { CacheEntry, DNSBLAnswer, DNSBLConfig } from './types.js';

/** Global DNSBL result cache */
const cache = new Map<string, CacheEntry>();

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

/**
 * Get cache entry if valid
 */
export function getCacheEntry(query: string, cacheTime: number): CacheEntry | null {
  const entry = cache.get(query);
  if (!entry) return null;

  const now = Date.now();
  // cacheTime <= 0 means always expired, otherwise check age
  if (cacheTime <= 0 || entry.ts <= now - cacheTime * 1000) {
    // Cache expired
    cache.delete(query);
    return null;
  }

  return entry;
}

/**
 * Set cache entry
 */
export function setCacheEntry(query: string, result: string[] | null): void {
  cache.set(query, {
    result,
    ts: Date.now(),
  });
}

/**
 * Get cache size for stats
 */
export function getCacheSize(): number {
  return cache.size;
}

/**
 * Delete a cache entry
 */
export function deleteCacheEntry(query: string): void {
  cache.delete(query);
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
