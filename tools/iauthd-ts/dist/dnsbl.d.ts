/**
 * DNSBL lookup module with caching
 */
import type { CacheEntry, DNSBLConfig } from './types.js';
/**
 * Reverse an IPv4 address for DNSBL lookup
 * e.g., "192.168.1.10" -> "10.1.168.192"
 */
export declare function reverseIPv4(ip: string): string | null;
/**
 * Check if an IP is IPv4
 */
export declare function isIPv4(ip: string): boolean;
/**
 * Get cache entry if valid
 */
export declare function getCacheEntry(query: string, cacheTime: number): CacheEntry | null;
/**
 * Set cache entry
 */
export declare function setCacheEntry(query: string, result: string[] | null): void;
/**
 * Get cache size for stats
 */
export declare function getCacheSize(): number;
/**
 * Perform a DNSBL lookup
 * Returns array of result IPs or empty array if not listed
 */
export declare function lookupDNSBL(reversedIp: string, dnsblServer: string, timeout: number): Promise<string[]>;
/**
 * Check if a DNSBL result matches the configuration
 */
export declare function matchesDNSBL(results: string[], config: DNSBLConfig): boolean;
/**
 * Parse DNSBL query to extract IP and server
 */
export declare function parseQuery(query: string): {
    ip: string;
    server: string;
} | null;
//# sourceMappingURL=dnsbl.d.ts.map