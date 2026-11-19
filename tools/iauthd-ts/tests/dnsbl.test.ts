/**
 * Unit tests for DNSBL functions
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { promises as dnsPromises } from 'node:dns';
import {
  reverseIPv4,
  isIPv4,
  getCacheEntry,
  setCacheEntry,
  getCacheSize,
  matchesDNSBL,
  parseQuery,
  lookupDNSBL,
  queryDNSBL,
  sweepCache,
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
      setCacheEntry(query, ['127.0.0.2'], 3600);

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
      setCacheEntry(query, ['127.0.0.2'], 3600);

      // With cacheTime of 0, entry should be expired
      const entry = getCacheEntry(query, 0);
      expect(entry).toBeNull();
    });

    it('should track cache size', () => {
      const initialSize = getCacheSize();
      const query = `test-cache-size-${Date.now()}.dnsbl.example.com`;
      setCacheEntry(query, ['127.0.0.2'], 3600);

      expect(getCacheSize()).toBeGreaterThanOrEqual(initialSize);
    });

    it('should store a definite "not listed" as an empty result', () => {
      const query = 'test-cache-empty.dnsbl.example.com';
      setCacheEntry(query, [], 3600);

      const entry = getCacheEntry(query, 3600);
      expect(entry).not.toBeNull();
      expect(entry?.result).toEqual([]);
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

  /** A rejection as node's dns.resolve4 gives it (err.code as seen against a real server) */
  function dnsError(code: string): Error {
    return Object.assign(new Error(`queryA ${code} x`), { code });
  }

  describe('lookupDNSBL', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('returns the A records as a definite answer', async () => {
      vi.spyOn(dnsPromises, 'resolve4').mockResolvedValue(['127.0.0.2'] as never);
      const answer = await lookupDNSBL('1.0.0.10', 'bl.example', 1);
      expect(answer).toEqual({ results: ['127.0.0.2'], definite: true });
      expect(dnsPromises.resolve4).toHaveBeenCalledWith('1.0.0.10.bl.example');
    });

    // NXDOMAIN and NODATA: the list says the address is not on it.
    for (const code of ['ENOTFOUND', 'ENODATA']) {
      it(`treats ${code} as a definite "not listed"`, async () => {
        vi.spyOn(dnsPromises, 'resolve4').mockRejectedValue(dnsError(code));
        const answer = await lookupDNSBL('1.0.0.10', 'bl.example', 1);
        expect(answer.results).toEqual([]);
        expect(answer.definite).toBe(true);
      });
    }

    // SERVFAIL, REFUSED, c-ares timeout, server unreachable, anything else:
    // no answer from the list -- "not listed" for now, but not definite.
    for (const code of ['ESERVFAIL', 'EREFUSED', 'ETIMEOUT', 'ECONNREFUSED', 'EBADRESP', undefined]) {
      it(`treats ${code ?? 'an error without a code'} as a failed lookup, not a definite answer`, async () => {
        const err = code ? dnsError(code) : new Error('boom');
        vi.spyOn(dnsPromises, 'resolve4').mockRejectedValue(err);
        const answer = await lookupDNSBL('1.0.0.10', 'bl.example', 1);
        expect(answer.results).toEqual([]);
        expect(answer.definite).toBe(false);
        expect(answer.error).toBeTruthy();
      });
    }

    it('gives up after the timeout with a failed (not definite) answer', async () => {
      vi.spyOn(dnsPromises, 'resolve4').mockReturnValue(new Promise(() => {}) as never);
      const t0 = Date.now();
      const answer = await lookupDNSBL('1.0.0.10', 'bl.example', 0.2);
      expect(Date.now() - t0).toBeLessThan(1000);
      expect(answer.results).toEqual([]);
      expect(answer.definite).toBe(false);
    });
  });

  describe('queryDNSBL (cache and lookups in flight)', () => {
    let n = 0;
    /** A reversed IP no other test has used: the cache is module-wide */
    const freshIp = () => `${++n}.0.77.10`;

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('a second query while the first is in flight shares its lookup and its answer', async () => {
      const spy = vi.spyOn(dnsPromises, 'resolve4').mockImplementation(
        () => new Promise(r => setTimeout(() => r(['127.0.0.2']), 300)) as never);
      const ip = freshIp();

      const first = queryDNSBL(ip, 'bl.example', 1, 3600);
      const second = queryDNSBL(ip, 'bl.example', 1, 3600);
      expect(first.source).toBe('lookup');
      expect(second.source).toBe('shared');

      expect(await second.answer).toEqual({ results: ['127.0.0.2'], definite: true });
      expect(await first.answer).toEqual({ results: ['127.0.0.2'], definite: true });
      expect(spy).toHaveBeenCalledTimes(1);
    });

    it('nothing is cached while a lookup is in flight', () => {
      vi.spyOn(dnsPromises, 'resolve4').mockReturnValue(new Promise(() => {}) as never);
      const ip = freshIp();
      queryDNSBL(ip, 'bl.example', 0.1, 3600);
      expect(getCacheEntry(`${ip}.bl.example`, 3600)).toBeNull();
    });

    it('a definite answer is cached: the next query does not ask again', async () => {
      const spy = vi.spyOn(dnsPromises, 'resolve4').mockRejectedValue(dnsError('ENOTFOUND'));
      const ip = freshIp();

      expect(await queryDNSBL(ip, 'bl.example', 1, 3600).answer).toEqual({ results: [], definite: true });
      const again = queryDNSBL(ip, 'bl.example', 1, 3600);
      expect(again.source).toBe('cache');
      expect(await again.answer).toEqual({ results: [], definite: true });
      expect(spy).toHaveBeenCalledTimes(1);
    });

    it('a failed shared lookup gives every waiter "not listed, not definite" and leaves nothing behind', async () => {
      const spy = vi.spyOn(dnsPromises, 'resolve4')
        .mockImplementationOnce(() => new Promise((_, rej) =>
          setTimeout(() => rej(dnsError('ESERVFAIL')), 100)) as never)
        .mockResolvedValue(['127.0.0.2'] as never);
      const ip = freshIp();

      const a = queryDNSBL(ip, 'bl.example', 1, 3600);
      const b = queryDNSBL(ip, 'bl.example', 1, 3600);
      for (const q of [a, b]) {
        const answer = await q.answer;
        expect(answer.results).toEqual([]);
        expect(answer.definite).toBe(false);
      }
      expect(getCacheEntry(`${ip}.bl.example`, 3600)).toBeNull();

      // Neither a cache entry nor the finished lookup is reused: ask again.
      const c = queryDNSBL(ip, 'bl.example', 1, 3600);
      expect(c.source).toBe('lookup');
      expect(await c.answer).toEqual({ results: ['127.0.0.2'], definite: true });
      expect(spy).toHaveBeenCalledTimes(2);
    });

    it('waiters on a lookup that never answers are released by the same timeout', async () => {
      vi.spyOn(dnsPromises, 'resolve4').mockReturnValue(new Promise(() => {}) as never);
      const ip = freshIp();
      const t0 = Date.now();

      const a = queryDNSBL(ip, 'bl.example', 0.3, 3600);
      await new Promise(r => setTimeout(r, 100));
      const b = queryDNSBL(ip, 'bl.example', 0.3, 3600);
      expect(b.source).toBe('shared');
      const [ra, rb] = await Promise.all([a.answer, b.answer]);

      expect(Date.now() - t0).toBeLessThan(1000);
      expect(ra.definite).toBe(false);
      expect(rb.definite).toBe(false);
      expect(rb.results).toEqual([]);
    });
  });

  // The cache holds only what may be reused, and expired answers do not
  // stay in it until the same address asks again.
  describe('cache growth', () => {
    let n = 0;
    const freshIp = () => `${++n}.0.88.10`;

    afterEach(() => {
      vi.useRealTimers();
      vi.restoreAllMocks();
    });

    it('an answer for a list with cache time 0 is not stored', async () => {
      vi.spyOn(dnsPromises, 'resolve4').mockResolvedValue(['127.0.0.2'] as never);
      const ip = freshIp();
      const size = getCacheSize();

      await queryDNSBL(ip, 'bl.example', 1, 0).answer;

      expect(getCacheSize()).toBe(size);
      expect(getCacheEntry(`${ip}.bl.example`, 3600)).toBeNull();
    });

    it('a shared lookup is stored when any line asking for it keeps answers', async () => {
      vi.spyOn(dnsPromises, 'resolve4').mockImplementation(
        () => new Promise(r => setTimeout(() => r(['127.0.0.2']), 50)) as never);
      const ip = freshIp();

      const a = queryDNSBL(ip, 'bl.example', 1, 0);      // cachetime=0 line starts it
      const b = queryDNSBL(ip, 'bl.example', 1, 3600);   // another line keeps answers
      expect(b.source).toBe('shared');
      await Promise.all([a.answer, b.answer]);

      expect(getCacheEntry(`${ip}.bl.example`, 3600)?.result).toEqual(['127.0.0.2']);
    });

    it('an entry lives no longer than the cache time it was stored for', () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      const q = `${freshIp()}.bl.example`;
      setCacheEntry(q, ['127.0.0.2'], 1);
      vi.setSystemTime(Date.now() + 2000);
      // a reader with a longer cache time does not revive it
      expect(getCacheEntry(q, 3600)).toBeNull();
    });

    it('a reader with cache time 0 does not throw away an answer another line keeps', () => {
      const q = `${freshIp()}.bl.example`;
      setCacheEntry(q, ['127.0.0.2'], 3600);
      expect(getCacheEntry(q, 0)).toBeNull();
      expect(getCacheEntry(q, 3600)?.result).toEqual(['127.0.0.2']);
    });

    it('sweepCache removes expired entries and keeps live ones', () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      const short = Array.from({ length: 10 }, () => `${freshIp()}.bl.example`);
      const long = `${freshIp()}.bl.example`;
      for (const q of short) setCacheEntry(q, [], 1);
      setCacheEntry(long, [], 3600);
      const size = getCacheSize();

      vi.setSystemTime(Date.now() + 2000);
      expect(sweepCache()).toBeGreaterThanOrEqual(10);

      expect(getCacheSize()).toBe(size - 10);
      expect(getCacheEntry(long, 3600)).not.toBeNull();
    });

    it('inserting sweeps by itself: expired entries do not pile up', () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      for (let i = 0; i < 10; i++) setCacheEntry(`${freshIp()}.bl.example`, [], 1);
      const size = getCacheSize();

      vi.setSystemTime(Date.now() + 2000);
      for (let i = 0; i < 600; i++) setCacheEntry(`${freshIp()}.bl.example`, [], 3600);

      // the 10 expired ones are gone without anybody reading them
      expect(getCacheSize()).toBe(size - 10 + 600);
    });
  });
});
