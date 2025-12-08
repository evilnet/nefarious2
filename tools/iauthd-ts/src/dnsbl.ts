/**
 * DNSBL lookup module with caching
 */

import { promises as dns } from 'node:dns';
import type { CacheEntry, DNSBLConfig } from './types.js';

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
 * Perform a DNSBL lookup
 * Returns array of result IPs or empty array if not listed
 */
export async function lookupDNSBL(
  reversedIp: string,
  dnsblServer: string,
  timeout: number
): Promise<string[]> {
  const query = `${reversedIp}.${dnsblServer}`;

  try {
    // Create a DNS resolver with timeout
    const resolver = new dns.Resolver();
    resolver.setServers(['8.8.8.8', '8.8.4.4']); // Use Google DNS as fallback

    // Race against timeout
    const timeoutPromise = new Promise<string[]>((_, reject) => {
      setTimeout(() => reject(new Error('DNS timeout')), timeout * 1000);
    });

    const lookupPromise = dns.resolve4(query);
    const result = await Promise.race([lookupPromise, timeoutPromise]);

    return result;
  } catch (err) {
    // NXDOMAIN or timeout = not listed
    return [];
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
