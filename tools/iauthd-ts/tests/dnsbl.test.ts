/**
 * Unit tests for DNSBL functions
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  reverseIPv4,
  isIPv4,
  getCacheEntry,
  setCacheEntry,
  getCacheSize,
  matchesDNSBL,
  parseQuery,
} from '../src/dnsbl.js';
import type { DNSBLConfig } from '../src/types.js';

describe('DNSBL Functions', () => {
  describe('reverseIPv4', () => {
    it('should reverse a valid IPv4 address', () => {
      expect(reverseIPv4('192.168.1.10')).toBe('10.1.168.192');
    });

    it('should handle 127.0.0.1', () => {
      expect(reverseIPv4('127.0.0.1')).toBe('1.0.0.127');
    });

    it('should handle 0.0.0.0', () => {
      expect(reverseIPv4('0.0.0.0')).toBe('0.0.0.0');
    });

    it('should handle 255.255.255.255', () => {
      expect(reverseIPv4('255.255.255.255')).toBe('255.255.255.255');
    });

    it('should return null for invalid IPv4', () => {
      expect(reverseIPv4('not-an-ip')).toBeNull();
    });

    it('should return null for IPv6 addresses', () => {
      expect(reverseIPv4('::1')).toBeNull();
      expect(reverseIPv4('2001:db8::1')).toBeNull();
    });

    it('should return null for partial IPs', () => {
      expect(reverseIPv4('192.168.1')).toBeNull();
      expect(reverseIPv4('192.168')).toBeNull();
    });

    it('should return null for IPs with invalid octets', () => {
      expect(reverseIPv4('192.168.1.256')).toBeNull();
      expect(reverseIPv4('192.168.1.1000')).toBeNull();
    });
  });

  describe('isIPv4', () => {
    it('should return true for valid IPv4 addresses', () => {
      expect(isIPv4('192.168.1.1')).toBe(true);
      expect(isIPv4('127.0.0.1')).toBe(true);
      expect(isIPv4('0.0.0.0')).toBe(true);
      expect(isIPv4('255.255.255.255')).toBe(true);
    });

    it('should return false for IPv6 addresses', () => {
      expect(isIPv4('::1')).toBe(false);
      expect(isIPv4('2001:db8::1')).toBe(false);
    });

    it('should return false for invalid strings', () => {
      expect(isIPv4('not-an-ip')).toBe(false);
      expect(isIPv4('')).toBe(false);
      expect(isIPv4('192.168.1')).toBe(false);
    });
  });

  describe('Cache functions', () => {
    beforeEach(() => {
      // Clear cache by setting entries and letting them expire
      // Note: In a real implementation, we'd want a clearCache() function
    });

    it('should store and retrieve cache entries', () => {
      const query = 'test-cache-1.dnsbl.example.com';
      setCacheEntry(query, ['127.0.0.2']);

      const entry = getCacheEntry(query, 3600);
      expect(entry).not.toBeNull();
      expect(entry?.result).toEqual(['127.0.0.2']);
    });

    it('should return null for non-existent entries', () => {
      const entry = getCacheEntry('nonexistent.query.com', 3600);
      expect(entry).toBeNull();
    });

    it('should expire old entries', () => {
      const query = 'test-cache-expire.dnsbl.example.com';
      setCacheEntry(query, ['127.0.0.2']);

      // With cacheTime of 0, entry should be expired
      const entry = getCacheEntry(query, 0);
      expect(entry).toBeNull();
    });

    it('should track cache size', () => {
      const initialSize = getCacheSize();
      const query = `test-cache-size-${Date.now()}.dnsbl.example.com`;
      setCacheEntry(query, ['127.0.0.2']);

      expect(getCacheSize()).toBeGreaterThanOrEqual(initialSize);
    });

    it('should handle null results (pending lookups)', () => {
      const query = 'test-cache-null.dnsbl.example.com';
      setCacheEntry(query, null);

      const entry = getCacheEntry(query, 3600);
      expect(entry).not.toBeNull();
      expect(entry?.result).toBeNull();
    });
  });

  describe('matchesDNSBL', () => {
    it('should match by index', () => {
      const config: DNSBLConfig = {
        cfgNum: 1,
        server: 'dnsbl.example.com',
        index: '2,3,4',
      };

      expect(matchesDNSBL(['127.0.0.2'], config)).toBe(true);
      expect(matchesDNSBL(['127.0.0.3'], config)).toBe(true);
      expect(matchesDNSBL(['127.0.0.4'], config)).toBe(true);
      expect(matchesDNSBL(['127.0.0.5'], config)).toBe(false);
      expect(matchesDNSBL(['127.0.0.1'], config)).toBe(false);
    });

    it('should match by bitmask', () => {
      const config: DNSBLConfig = {
        cfgNum: 1,
        server: 'dnsbl.example.com',
        bitmask: '2',  // Binary: 010
      };

      expect(matchesDNSBL(['127.0.0.2'], config)).toBe(true);   // 010 & 010 = 010
      expect(matchesDNSBL(['127.0.0.3'], config)).toBe(true);   // 011 & 010 = 010
      expect(matchesDNSBL(['127.0.0.6'], config)).toBe(true);   // 110 & 010 = 010
      expect(matchesDNSBL(['127.0.0.1'], config)).toBe(false);  // 001 & 010 = 000
      expect(matchesDNSBL(['127.0.0.4'], config)).toBe(false);  // 100 & 010 = 000
    });

    it('should match multiple bitmasks', () => {
      const config: DNSBLConfig = {
        cfgNum: 1,
        server: 'dnsbl.example.com',
        bitmask: '2,4',  // Match if bit 1 or bit 2 set
      };

      expect(matchesDNSBL(['127.0.0.2'], config)).toBe(true);
      expect(matchesDNSBL(['127.0.0.4'], config)).toBe(true);
      expect(matchesDNSBL(['127.0.0.6'], config)).toBe(true);
      expect(matchesDNSBL(['127.0.0.1'], config)).toBe(false);
    });

    it('should match any result if no index or bitmask', () => {
      const config: DNSBLConfig = {
        cfgNum: 1,
        server: 'dnsbl.example.com',
      };

      expect(matchesDNSBL(['127.0.0.1'], config)).toBe(true);
      expect(matchesDNSBL(['127.0.0.255'], config)).toBe(true);
    });

    it('should not match empty results', () => {
      const config: DNSBLConfig = {
        cfgNum: 1,
        server: 'dnsbl.example.com',
        index: '2',
      };

      expect(matchesDNSBL([], config)).toBe(false);
    });

    it('should match if any result matches (multiple results)', () => {
      const config: DNSBLConfig = {
        cfgNum: 1,
        server: 'dnsbl.example.com',
        index: '4',
      };

      expect(matchesDNSBL(['127.0.0.2', '127.0.0.4'], config)).toBe(true);
      expect(matchesDNSBL(['127.0.0.1', '127.0.0.2'], config)).toBe(false);
    });

    it('should handle invalid result IPs gracefully', () => {
      const config: DNSBLConfig = {
        cfgNum: 1,
        server: 'dnsbl.example.com',
        index: '2',
      };

      expect(matchesDNSBL(['invalid', '127.0.0.2'], config)).toBe(true);
      expect(matchesDNSBL(['invalid'], config)).toBe(false);
    });
  });

  describe('parseQuery', () => {
    it('should parse a valid DNSBL query', () => {
      const result = parseQuery('10.1.168.192.dnsbl.example.com');
      expect(result).not.toBeNull();
      expect(result?.ip).toBe('192.168.1.10');
      expect(result?.server).toBe('dnsbl.example.com');
    });

    it('should handle multi-part server names', () => {
      const result = parseQuery('1.0.0.127.zen.spamhaus.org');
      expect(result).not.toBeNull();
      expect(result?.ip).toBe('127.0.0.1');
      expect(result?.server).toBe('zen.spamhaus.org');
    });

    it('should return null for invalid queries', () => {
      expect(parseQuery('invalid')).toBeNull();
      expect(parseQuery('dnsbl.example.com')).toBeNull();
      expect(parseQuery('')).toBeNull();
    });
  });
});
