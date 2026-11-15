/**
 * DNSBL Integration Tests with Mocked DNS
 *
 * Tests the full pipeline: client connect → DNSBL lookup → decision
 * Uses mock DNS responses to test all matching modes and edge cases.
 *
 * Based on real-world AfterNET production config.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { spawn, ChildProcess } from 'node:child_process';
import { writeFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createInterface } from 'node:readline';

/**
 * Mock DNS responses for testing
 * Maps reversed-IP.dnsbl-server to response IP(s)
 */
const mockDnsResponses: Map<string, string[] | MockDnsSpec> = new Map();

/**
 * One answer of a scripted mock: A records, an error code (as node's
 * dns.resolve4 reports it: ENOTFOUND, ENODATA, ESERVFAIL, ETIMEOUT, ...),
 * or no answer at all (hang), optionally after delayMs.
 */
interface MockDnsStep {
  answers?: string[];
  code?: string;
  hang?: boolean;
  delayMs?: number;
}

/** A scripted mock: the n-th query of the name gets steps[n-1] (the last step repeats). */
interface MockDnsSpec {
  steps: MockDnsStep[];
}

/**
 * Set up a mock DNS response
 */
function mockDns(clientIp: string, dnsblServer: string, responses: string[] | MockDnsSpec): void {
  const reversed = clientIp.split('.').reverse().join('.');
  const query = `${reversed}.${dnsblServer}`;
  mockDnsResponses.set(query, responses);
}

/**
 * Clear all mock DNS responses
 */
function clearMockDns(): void {
  mockDnsResponses.clear();
}

interface TestHarness {
  proc: ChildProcess;
  output: string[];
  /** Every name the daemon asked the mock DNS for, in order */
  dnsQueries: string[];
  send: (line: string) => void;
  waitFor: (pattern: RegExp, timeout?: number) => Promise<string>;
  getMarks: (clientId: number) => string[];
  wasAccepted: (clientId: number) => boolean;
  wasRejected: (clientId: number) => boolean;
  close: () => Promise<void>;
}

/**
 * Create a test harness with mock DNS injection
 */
async function createHarness(configPath: string): Promise<TestHarness> {
  const output: string[] = [];

  // Create a wrapper script that injects our mock DNS module
  const wrapperPath = join(tmpdir(), `dns-mock-${Date.now()}.mjs`);
  const mockResponses = JSON.stringify(Array.from(mockDnsResponses.entries()));

  writeFileSync(wrapperPath, `
import { promises as dns } from 'node:dns';

// Mock DNS responses
const mockResponses = new Map(${mockResponses});

// Override dns.resolve4
const originalResolve4 = dns.resolve4.bind(dns);
const queryCounts = new Map();
dns.resolve4 = async (hostname) => {
  const mock = mockResponses.get(hostname);
  const n = (queryCounts.get(hostname) ?? 0) + 1;
  queryCounts.set(hostname, n);
  process.stderr.write('mockdns-query ' + hostname + '\\n');
  if (mock !== undefined && !Array.isArray(mock)) {
    const step = mock.steps[Math.min(n, mock.steps.length) - 1];
    if (step.delayMs) await new Promise((r) => setTimeout(r, step.delayMs));
    if (step.hang) return new Promise(() => {});
    if (step.code) {
      const err = new Error('queryA ' + step.code + ' ' + hostname);
      err.code = step.code;
      throw err;
    }
    return step.answers ?? [];
  }
  if (mock !== undefined) {
    if (mock.length === 0) {
      const err = new Error('NXDOMAIN');
      err.code = 'ENOTFOUND';
      throw err;
    }
    return mock;
  }
  // For non-mocked queries, return NXDOMAIN (not listed)
  const err = new Error('NXDOMAIN');
  err.code = 'ENOTFOUND';
  throw err;
};

// Now import and run the actual daemon
import('${join(import.meta.dirname, '..', 'src', 'index.ts').replace(/\\/g, '/')}');
`);

  const proc = spawn('npx', ['tsx', wrapperPath, '-v', '-c', configPath], {
    cwd: join(import.meta.dirname, '..'),
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env },
  });

  const rl = createInterface({ input: proc.stdout! });
  rl.on('line', (line) => output.push(line));

  const dnsQueries: string[] = [];
  const errRl = createInterface({ input: proc.stderr! });
  errRl.on('line', (line) => {
    const m = line.match(/^mockdns-query (\S+)/);
    if (m) dnsQueries.push(m[1]);
    // Uncomment for debugging:
    // else console.error('stderr:', line);
  });

  const send = (line: string) => {
    proc.stdin!.write(line + '\n');
  };

  const waitFor = (pattern: RegExp, timeout = 5000): Promise<string> => {
    return new Promise((resolve, reject) => {
      // Check existing output
      for (const line of output) {
        if (pattern.test(line)) {
          resolve(line);
          return;
        }
      }

      const startLen = output.length;
      const interval = setInterval(() => {
        for (let i = startLen; i < output.length; i++) {
          if (pattern.test(output[i])) {
            clearInterval(interval);
            clearTimeout(timer);
            resolve(output[i]);
            return;
          }
        }
      }, 10);

      const timer = setTimeout(() => {
        clearInterval(interval);
        reject(new Error(`Timeout waiting for: ${pattern}\nOutput was:\n${output.join('\n')}`));
      }, timeout);
    });
  };

  const getMarks = (clientId: number): string[] => {
    const marks: string[] = [];
    const pattern = new RegExp(`^m ${clientId} .* MARK (\\S+)`);
    for (const line of output) {
      const match = line.match(pattern);
      if (match) {
        marks.push(match[1]);
      }
    }
    return marks;
  };

  const wasAccepted = (clientId: number): boolean => {
    return output.some(line => line.startsWith(`D ${clientId} `));
  };

  const wasRejected = (clientId: number): boolean => {
    return output.some(line => line.startsWith(`k ${clientId} `));
  };

  const close = async (): Promise<void> => {
    try { unlinkSync(wrapperPath); } catch {}
    return new Promise((resolve) => {
      proc.on('close', () => resolve());
      proc.stdin!.end();
      setTimeout(() => {
        proc.kill('SIGTERM');
        resolve();
      }, 1000);
    });
  };

  // Wait for startup
  await waitFor(/^S iauthd-ts/);
  await new Promise(r => setTimeout(r, 100));

  return { proc, output, dnsQueries, send, waitFor, getMarks, wasAccepted, wasRejected, close };
}

/**
 * Simulate a full client connection flow
 */
async function connectClient(
  harness: TestHarness,
  clientId: number,
  ip: string,
  options: { authenticated?: string } = {}
): Promise<void> {
  harness.send(`${clientId} C ${ip} ${10000 + clientId} 10.0.0.1 6667`);

  if (options.authenticated) {
    harness.send(`${clientId} R ${options.authenticated}`);
  }

  // Small delay to let lookups start
  await new Promise(r => setTimeout(r, 50));

  harness.send(`${clientId} H Users`);

  // Wait for decision
  await harness.waitFor(new RegExp(`^[Dk] ${clientId} `), 3000);
}

describe('DNSBL Integration Tests', () => {
  let tempDir: string;
  let configPath: string;
  let harness: TestHarness;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'iauthd-dnsbl-test-'));
    configPath = join(tempDir, 'test.conf');
    clearMockDns();
  });

  afterEach(async () => {
    await harness?.close();
    try { unlinkSync(configPath); } catch {}
  });

  describe('Index Matching', () => {
    beforeEach(async () => {
      writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH DNSBL server=test.dnsbl index=2,3,4 mark=testbl block=all
`);
    });

    it('should block when index matches exactly', async () => {
      mockDns('192.168.1.100', 'test.dnsbl', ['127.0.0.2']);
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.100');

      expect(harness.wasRejected(0)).toBe(true);
      expect(harness.wasAccepted(0)).toBe(false);
    });

    it('should block when any configured index matches', async () => {
      mockDns('192.168.1.101', 'test.dnsbl', ['127.0.0.4']);
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.101');

      expect(harness.wasRejected(0)).toBe(true);
    });

    it('should pass when index does not match', async () => {
      mockDns('192.168.1.102', 'test.dnsbl', ['127.0.0.5']); // index=5 not in 2,3,4
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.102');

      expect(harness.wasAccepted(0)).toBe(true);
      expect(harness.wasRejected(0)).toBe(false);
    });

    it('should pass when not listed (NXDOMAIN)', async () => {
      // No mock = NXDOMAIN
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.103');

      expect(harness.wasAccepted(0)).toBe(true);
    });
  });

  describe('Bitmask Matching', () => {
    beforeEach(async () => {
      writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH DNSBL server=test.dnsbl bitmask=2,4 mark=testbl block=all
`);
    });

    it('should block when bitmask matches (bit 1 set)', async () => {
      mockDns('192.168.1.100', 'test.dnsbl', ['127.0.0.2']); // 2 = 0010
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.100');

      expect(harness.wasRejected(0)).toBe(true);
    });

    it('should block when bitmask matches (bit 2 set)', async () => {
      mockDns('192.168.1.101', 'test.dnsbl', ['127.0.0.4']); // 4 = 0100
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.101');

      expect(harness.wasRejected(0)).toBe(true);
    });

    it('should block when multiple bits match', async () => {
      mockDns('192.168.1.102', 'test.dnsbl', ['127.0.0.6']); // 6 = 0110 (bits 1 and 2)
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.102');

      expect(harness.wasRejected(0)).toBe(true);
    });

    it('should pass when no bitmask bits match', async () => {
      mockDns('192.168.1.103', 'test.dnsbl', ['127.0.0.1']); // 1 = 0001 (bit 0 only)
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.103');

      expect(harness.wasAccepted(0)).toBe(true);
    });
  });

  describe('Block Modes', () => {
    describe('block=all', () => {
      beforeEach(async () => {
        writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH DNSBL server=test.dnsbl index=2 mark=testbl block=all
`);
      });

      it('should block unauthenticated users', async () => {
        mockDns('192.168.1.100', 'test.dnsbl', ['127.0.0.2']);
        harness = await createHarness(configPath);

        await connectClient(harness, 0, '192.168.1.100');

        expect(harness.wasRejected(0)).toBe(true);
      });

      it('should block authenticated users too', async () => {
        mockDns('192.168.1.100', 'test.dnsbl', ['127.0.0.2']);
        harness = await createHarness(configPath);

        await connectClient(harness, 0, '192.168.1.100', { authenticated: 'testuser' });

        expect(harness.wasRejected(0)).toBe(true);
      });
    });

    describe('block=anonymous', () => {
      beforeEach(async () => {
        writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH BLOCKMSG You must authenticate to connect.
#IAUTH DNSBL server=test.dnsbl index=2 mark=testbl block=anonymous
`);
      });

      it('should block unauthenticated users', async () => {
        mockDns('192.168.1.100', 'test.dnsbl', ['127.0.0.2']);
        harness = await createHarness(configPath);

        await connectClient(harness, 0, '192.168.1.100');

        expect(harness.wasRejected(0)).toBe(true);
      });

      it('should allow SASL-authenticated users', async () => {
        mockDns('192.168.1.100', 'test.dnsbl', ['127.0.0.2']);
        harness = await createHarness(configPath);

        await connectClient(harness, 0, '192.168.1.100', { authenticated: 'gooduser' });

        expect(harness.wasAccepted(0)).toBe(true);
        expect(harness.wasRejected(0)).toBe(false);
      });

      it('should mark authenticated users even though not blocked', async () => {
        mockDns('192.168.1.100', 'test.dnsbl', ['127.0.0.2']);
        harness = await createHarness(configPath);

        await connectClient(harness, 0, '192.168.1.100', { authenticated: 'gooduser' });

        expect(harness.wasAccepted(0)).toBe(true);
        expect(harness.getMarks(0)).toContain('testbl');
      });
    });

    describe('mark only (no block)', () => {
      beforeEach(async () => {
        writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH DNSBL server=test.dnsbl index=2 mark=infomark
`);
      });

      it('should accept client but apply mark', async () => {
        mockDns('192.168.1.100', 'test.dnsbl', ['127.0.0.2']);
        harness = await createHarness(configPath);

        await connectClient(harness, 0, '192.168.1.100');

        expect(harness.wasAccepted(0)).toBe(true);
        expect(harness.getMarks(0)).toContain('infomark');
      });
    });
  });

  describe('Whitelist', () => {
    beforeEach(async () => {
      // Whitelist first, then blocking DNSBLs - mimics AfterNET config
      writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH DNSBL server=whitelist.dnsbl index=2 mark=whitelist whitelist
#IAUTH DNSBL server=blocklist.dnsbl index=2 mark=blocked block=all
`);
    });

    it('should not block whitelisted clients even if they match blocking DNSBL', async () => {
      mockDns('192.168.1.100', 'whitelist.dnsbl', ['127.0.0.2']); // Whitelisted
      mockDns('192.168.1.100', 'blocklist.dnsbl', ['127.0.0.2']); // Also on blocklist
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.100');

      expect(harness.wasAccepted(0)).toBe(true);
      expect(harness.wasRejected(0)).toBe(false);
    });

    it('should block non-whitelisted clients that match blocking DNSBL', async () => {
      // Not on whitelist, but on blocklist
      mockDns('192.168.1.101', 'blocklist.dnsbl', ['127.0.0.2']);
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.101');

      expect(harness.wasRejected(0)).toBe(true);
    });

    it('should apply whitelist mark', async () => {
      mockDns('192.168.1.100', 'whitelist.dnsbl', ['127.0.0.2']);
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.100');

      expect(harness.getMarks(0)).toContain('whitelist');
    });
  });

  describe('Multiple DNSBLs', () => {
    beforeEach(async () => {
      writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH DNSBL server=dnsbl1.test index=2 mark=list1
#IAUTH DNSBL server=dnsbl2.test index=2 mark=list2
#IAUTH DNSBL server=dnsbl3.test index=2 mark=list3 block=anonymous
`);
    });

    it('should accumulate marks from multiple DNSBLs', async () => {
      mockDns('192.168.1.100', 'dnsbl1.test', ['127.0.0.2']);
      mockDns('192.168.1.100', 'dnsbl2.test', ['127.0.0.2']);
      // Not on dnsbl3
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.100');

      expect(harness.wasAccepted(0)).toBe(true);
      const marks = harness.getMarks(0);
      expect(marks).toContain('list1');
      expect(marks).toContain('list2');
      expect(marks).not.toContain('list3');
    });

    it('should block if any blocking DNSBL matches', async () => {
      mockDns('192.168.1.100', 'dnsbl3.test', ['127.0.0.2']);
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.100');

      expect(harness.wasRejected(0)).toBe(true);
    });
  });

  describe('Same Server, Different Indices (AfterNET pattern)', () => {
    beforeEach(async () => {
      // Mimics AfterNET's dnsbl.afternet.org with different indices
      writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH DNSBL server=dnsbl.example.org index=2 mark=whitelist whitelist
#IAUTH DNSBL server=dnsbl.example.org index=250 mark=rbl block=anonymous
#IAUTH DNSBL server=dnsbl.example.org index=251 mark=cloud block=anonymous
`);
    });

    it('should whitelist on index=2', async () => {
      mockDns('192.168.1.100', 'dnsbl.example.org', ['127.0.0.2']);
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.100');

      expect(harness.wasAccepted(0)).toBe(true);
      expect(harness.getMarks(0)).toContain('whitelist');
    });

    it('should block anonymous on index=250', async () => {
      mockDns('192.168.1.101', 'dnsbl.example.org', ['127.0.0.250']);
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.101');

      expect(harness.wasRejected(0)).toBe(true);
    });

    it('should block anonymous on index=251', async () => {
      mockDns('192.168.1.102', 'dnsbl.example.org', ['127.0.0.251']);
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.102');

      expect(harness.wasRejected(0)).toBe(true);
    });

    it('should allow authenticated on index=250', async () => {
      mockDns('192.168.1.101', 'dnsbl.example.org', ['127.0.0.250']);
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.101', { authenticated: 'user' });

      expect(harness.wasAccepted(0)).toBe(true);
      expect(harness.getMarks(0)).toContain('rbl');
    });
  });

  describe('Real-world AfterNET Config Simulation', () => {
    beforeEach(async () => {
      writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH CACHETIMEOUT 21600
#IAUTH DNSTIMEOUT 5
#IAUTH BLOCKMSG Sorry! Your connection has been rejected due to poor reputation.
#IAUTH DNSBL server=dnsbl.afternet.org index=2 mark=whitelist whitelist
#IAUTH DNSBL server=dnsbl.afternet.org index=250 mark=afternetrbl block=anonymous
#IAUTH DNSBL server=dnsbl.afternet.org index=251 mark=cloud block=anonymous
#IAUTH DNSBL server=dnsbl.sorbs.net index=2,3,4,5,6,7,9 mark=sorbs block=anonymous
#IAUTH DNSBL server=dnsbl.dronebl.org index=2,3,5,6,7,8,9,10,13,14,15 mark=dronebl block=anonymous
#IAUTH DNSBL server=rbl.efnetrbl.org index=4 mark=tor block=anonymous
#IAUTH DNSBL server=rbl.efnetrbl.org index=1,2,3,5 mark=efnetrbl block=anonymous
#IAUTH DNSBL server=dnsbl-2.uceprotect.net index=2 mark=uce-2
#IAUTH DNSBL server=cbl.abuseat.org index=2 mark=cbl
`);
    });

    it('should accept clean clients', async () => {
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '8.8.8.8');

      expect(harness.wasAccepted(0)).toBe(true);
      expect(harness.getMarks(0)).toHaveLength(0);
    });

    it('should whitelist AfterNET trusted IPs', async () => {
      mockDns('10.0.0.50', 'dnsbl.afternet.org', ['127.0.0.2']);
      mockDns('10.0.0.50', 'dnsbl.dronebl.org', ['127.0.0.5']); // Also on dronebl!
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '10.0.0.50');

      expect(harness.wasAccepted(0)).toBe(true);
      expect(harness.getMarks(0)).toContain('whitelist');
    });

    it('should block drones unless authenticated', async () => {
      mockDns('10.0.0.60', 'dnsbl.dronebl.org', ['127.0.0.5']);
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '10.0.0.60');

      expect(harness.wasRejected(0)).toBe(true);
    });

    it('should allow authenticated drones', async () => {
      mockDns('10.0.0.60', 'dnsbl.dronebl.org', ['127.0.0.5']);
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '10.0.0.60', { authenticated: 'droneuser' });

      expect(harness.wasAccepted(0)).toBe(true);
      expect(harness.getMarks(0)).toContain('dronebl');
    });

    it('should block Tor exit nodes unless authenticated', async () => {
      mockDns('10.0.0.70', 'rbl.efnetrbl.org', ['127.0.0.4']); // index=4 = tor
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '10.0.0.70');

      expect(harness.wasRejected(0)).toBe(true);
    });

    it('should mark UCE-2 but not block', async () => {
      mockDns('10.0.0.80', 'dnsbl-2.uceprotect.net', ['127.0.0.2']);
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '10.0.0.80');

      expect(harness.wasAccepted(0)).toBe(true);
      expect(harness.getMarks(0)).toContain('uce-2');
    });

    it('should mark CBL but not block', async () => {
      mockDns('10.0.0.90', 'cbl.abuseat.org', ['127.0.0.2']);
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '10.0.0.90');

      expect(harness.wasAccepted(0)).toBe(true);
      expect(harness.getMarks(0)).toContain('cbl');
    });

    it('should accumulate multiple marks', async () => {
      mockDns('10.0.0.95', 'dnsbl-2.uceprotect.net', ['127.0.0.2']);
      mockDns('10.0.0.95', 'cbl.abuseat.org', ['127.0.0.2']);
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '10.0.0.95');

      expect(harness.wasAccepted(0)).toBe(true);
      const marks = harness.getMarks(0);
      expect(marks).toContain('uce-2');
      expect(marks).toContain('cbl');
    });
  });

  describe('Class Assignment', () => {
    beforeEach(async () => {
      writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH DNSBL server=trusted.dnsbl index=2 class=Trusted mark=trusted
#IAUTH DNSBL server=limited.dnsbl index=2 class=Limited mark=limited
`);
    });

    it('should assign class from matching DNSBL', async () => {
      mockDns('192.168.1.100', 'trusted.dnsbl', ['127.0.0.2']);
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '192.168.1.100');

      expect(harness.wasAccepted(0)).toBe(true);
      // Check the D message includes the class
      const acceptLine = harness.output.find(l => l.startsWith('D 0 '));
      expect(acceptLine).toContain('Trusted');
    });
  });

  // Only a definite answer (A records, NXDOMAIN, NODATA) is cached.  A lookup
  // that times out or fails counts as "not listed" for that one client and is
  // asked again for the next connection from the address.
  describe('Failed lookups are not cached', () => {
    beforeEach(async () => {
      writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH DNSTIMEOUT 1
#IAUTH CACHETIME 3600
#IAUTH DNSBL server=wl.dnsbl index=2 whitelist
#IAUTH DNSBL server=block.dnsbl index=2 block=all
`);
    });

    for (const code of ['ESERVFAIL', 'EREFUSED', 'ECONNREFUSED', 'ETIMEOUT']) {
      it(`a block list failing once (${code}) passes that client only; the next connection is asked again`, async () => {
        mockDns('10.1.0.1', 'block.dnsbl', { steps: [{ code }, { answers: ['127.0.0.2'] }] });
        harness = await createHarness(configPath);

        await connectClient(harness, 0, '10.1.0.1');
        expect(harness.wasAccepted(0)).toBe(true);

        await connectClient(harness, 1, '10.1.0.1');
        expect(harness.wasRejected(1)).toBe(true);
        expect(harness.dnsQueries.filter(q => q === '1.0.1.10.block.dnsbl')).toHaveLength(2);
      });
    }

    it('a block list that never answers passes the client in bounded time; the next connection is asked again', async () => {
      mockDns('10.1.0.2', 'block.dnsbl', { steps: [{ hang: true }, { answers: ['127.0.0.2'] }] });
      harness = await createHarness(configPath);

      const t0 = Date.now();
      await connectClient(harness, 0, '10.1.0.2');
      expect(harness.wasAccepted(0)).toBe(true);
      expect(Date.now() - t0).toBeLessThan(2500);

      await connectClient(harness, 1, '10.1.0.2');
      expect(harness.wasRejected(1)).toBe(true);
    });

    it('a whitelist slow once does not refuse the whitelisted address for CACHETIME', async () => {
      mockDns('10.1.0.3', 'wl.dnsbl', { steps: [{ hang: true }, { answers: ['127.0.0.2'] }] });
      mockDns('10.1.0.3', 'block.dnsbl', ['127.0.0.2']);
      harness = await createHarness(configPath);

      // The whitelist did not answer in time: for this client it is not listed.
      await connectClient(harness, 0, '10.1.0.3');
      expect(harness.wasRejected(0)).toBe(true);

      // The next connection asks the whitelist again and is let in.
      await connectClient(harness, 1, '10.1.0.3');
      expect(harness.wasAccepted(1)).toBe(true);
      expect(harness.wasRejected(1)).toBe(false);
    });

    for (const code of ['ENOTFOUND', 'ENODATA']) {
      it(`a definite "not listed" (${code}) is cached`, async () => {
        mockDns('10.1.0.4', 'block.dnsbl', { steps: [{ code }, { answers: ['127.0.0.2'] }] });
        harness = await createHarness(configPath);

        await connectClient(harness, 0, '10.1.0.4');
        await connectClient(harness, 1, '10.1.0.4');

        expect(harness.wasAccepted(0)).toBe(true);
        expect(harness.wasAccepted(1)).toBe(true);
        expect(harness.dnsQueries.filter(q => q === '4.0.1.10.block.dnsbl')).toHaveLength(1);
      });
    }

    it('a listed answer is cached', async () => {
      mockDns('10.1.0.5', 'block.dnsbl', { steps: [{ answers: ['127.0.0.2'] }, { code: 'ENOTFOUND' }] });
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '10.1.0.5');
      await connectClient(harness, 1, '10.1.0.5');

      expect(harness.wasRejected(0)).toBe(true);
      expect(harness.wasRejected(1)).toBe(true);
      expect(harness.dnsQueries.filter(q => q === '5.0.1.10.block.dnsbl')).toHaveLength(1);
    });
  });

  // A second connection from an address whose lookup is still in flight
  // waits for that same lookup and is judged by its answer.
  describe('Lookups in flight are shared', () => {
    /** Introduce several clients at once, then hurry them all and wait for every decision. */
    async function connectTogether(clients: Array<[number, string]>): Promise<void> {
      for (const [id, ip] of clients) {
        harness.send(`${id} C ${ip} ${10000 + id} 10.0.0.1 6667`);
        await new Promise(r => setTimeout(r, 20));
      }
      for (const [id] of clients) harness.send(`${id} H Users`);
      for (const [id] of clients) await harness.waitFor(new RegExp(`^[Dk] ${id} `), 3000);
    }

    beforeEach(async () => {
      writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH DNSTIMEOUT 1
#IAUTH CACHETIME 3600
#IAUTH DNSBL server=block.dnsbl index=2 block=all
#IAUTH DNSBL server=mark.dnsbl index=2 mark=mk
#IAUTH DNSBL server=multi.dnsbl index=2 whitelist
#IAUTH DNSBL server=multi.dnsbl index=250 block=anonymous
`);
    });

    it('two simultaneous connections from a block-listed address are both refused, with one lookup', async () => {
      mockDns('10.2.0.1', 'block.dnsbl', { steps: [{ answers: ['127.0.0.2'], delayMs: 500 }] });
      harness = await createHarness(configPath);

      await connectTogether([[0, '10.2.0.1'], [1, '10.2.0.1']]);

      expect(harness.wasRejected(0)).toBe(true);
      expect(harness.wasRejected(1)).toBe(true);
      expect(harness.dnsQueries.filter(q => q === '1.0.2.10.block.dnsbl')).toHaveLength(1);
    });

    it('two simultaneous connections from a mark-listed address are both marked', async () => {
      mockDns('10.2.0.2', 'mark.dnsbl', { steps: [{ answers: ['127.0.0.2'], delayMs: 500 }] });
      harness = await createHarness(configPath);

      await connectTogether([[0, '10.2.0.2'], [1, '10.2.0.2']]);

      expect(harness.wasAccepted(0)).toBe(true);
      expect(harness.wasAccepted(1)).toBe(true);
      expect(harness.getMarks(0)).toContain('mk');
      expect(harness.getMarks(1)).toContain('mk');
    });

    it('two lines for one list (AfterNET pattern) both see a slow answer', async () => {
      // One query serves both lines; the answer matches the second line.
      mockDns('10.2.0.3', 'multi.dnsbl', { steps: [{ answers: ['127.0.0.250'], delayMs: 400 }] });
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '10.2.0.3');

      expect(harness.wasRejected(0)).toBe(true);
      expect(harness.dnsQueries.filter(q => q === '3.0.2.10.multi.dnsbl')).toHaveLength(1);
    });

    it('a shared lookup that fails passes every waiting client and is asked again next time', async () => {
      mockDns('10.2.0.4', 'block.dnsbl', {
        steps: [{ code: 'ESERVFAIL', delayMs: 300 }, { answers: ['127.0.0.2'] }],
      });
      harness = await createHarness(configPath);

      await connectTogether([[0, '10.2.0.4'], [1, '10.2.0.4']]);
      expect(harness.wasAccepted(0)).toBe(true);
      expect(harness.wasAccepted(1)).toBe(true);

      await connectClient(harness, 2, '10.2.0.4');
      expect(harness.wasRejected(2)).toBe(true);
      expect(harness.dnsQueries.filter(q => q === '4.0.2.10.block.dnsbl')).toHaveLength(2);
    });

    it('clients waiting on a shared lookup that never answers are all let through by the timeout', async () => {
      mockDns('10.2.0.5', 'block.dnsbl', { steps: [{ hang: true }, { answers: ['127.0.0.2'] }] });
      harness = await createHarness(configPath);

      const t0 = Date.now();
      await connectTogether([[0, '10.2.0.5'], [1, '10.2.0.5']]);
      expect(Date.now() - t0).toBeLessThan(2500);
      expect(harness.wasAccepted(0)).toBe(true);
      expect(harness.wasAccepted(1)).toBe(true);

      await connectClient(harness, 2, '10.2.0.5');
      expect(harness.wasRejected(2)).toBe(true);
    });
  });

  // The ircd uses the connection's fd as the IAuth client id, so an id comes
  // back as soon as a client has gone.  A lookup that finishes after its
  // client has gone must not act on whoever holds the id by then.
  describe('Lookups that finish after their client has gone', () => {
    beforeEach(async () => {
      writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH DNSTIMEOUT 2
#IAUTH DNSBL server=block.dnsbl index=2 block=all
`);
    });

    const pause = (ms: number) => new Promise(r => setTimeout(r, ms));

    it('a departed client\'s late answer leaves the id\'s new owner alone', async () => {
      mockDns('10.3.0.1', 'block.dnsbl', { steps: [{ answers: ['127.0.0.2'], delayMs: 600 }] });
      // 10.3.0.2 is not listed (NXDOMAIN at once)
      harness = await createHarness(configPath);

      // A (id 40) is hurried while its list is slow, then disconnects.
      harness.send('40 C 10.3.0.1 10040 10.0.0.1 6667');
      await pause(50);
      harness.send('40 H Users');
      await pause(50);
      harness.send('40 D');
      await pause(50);
      // B gets the same id; A's list answers while B is being checked.
      harness.send('40 C 10.3.0.2 20040 10.0.0.1 6667');
      await pause(1000);
      harness.send('40 H Users');

      await harness.waitFor(/^D 40 10\.3\.0\.2 20040/, 3000);
      expect(harness.output.filter(l => /^[Dkm] 40 10\.3\.0\.1 /.test(l))).toEqual([]);
        }, 10000);

    it('the lookup for the address a trusted WEBIRC replaced sends nothing when it finishes', async () => {
      mockDns('10.3.0.3', 'block.dnsbl', { steps: [{ answers: ['127.0.0.2'], delayMs: 600 }] });
      harness = await createHarness(configPath);

      harness.send('41 C 10.3.0.3 10041 10.0.0.1 6667');
      await pause(50);
      harness.send('41 H Users');
      await pause(50);
      harness.send('41 w pass user host.example 10.3.0.4');

      await harness.waitFor(/^D 41 10\.3\.0\.4 10041/, 3000);
      await pause(1000); // the gateway address's answer arrives
      expect(harness.output.filter(l => /^[Dkm] 41 10\.3\.0\.3 /.test(l))).toEqual([]);
    });
  });

  describe('CACHETIME 0', () => {
    it('asks the list again for every connection', async () => {
      writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH CACHETIME 0
#IAUTH DNSBL server=block.dnsbl index=2 block=all
`);
      mockDns('10.4.0.1', 'block.dnsbl', { steps: [{ answers: ['127.0.0.2'] }, { code: 'ENOTFOUND' }] });
      harness = await createHarness(configPath);

      await connectClient(harness, 0, '10.4.0.1');
      await connectClient(harness, 1, '10.4.0.1');

      expect(harness.wasRejected(0)).toBe(true);
      expect(harness.wasAccepted(1)).toBe(true);
      expect(harness.dnsQueries.filter(q => q === '1.0.4.10.block.dnsbl')).toHaveLength(2);
    });
  });
});
