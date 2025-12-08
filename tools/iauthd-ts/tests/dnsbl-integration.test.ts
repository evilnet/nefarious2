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
const mockDnsResponses: Map<string, string[]> = new Map();

/**
 * Set up a mock DNS response
 */
function mockDns(clientIp: string, dnsblServer: string, responses: string[]): void {
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
dns.resolve4 = async (hostname) => {
  const mock = mockResponses.get(hostname);
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

  proc.stderr?.on('data', (data) => {
    // Uncomment for debugging:
    // console.error('stderr:', data.toString());
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

  return { proc, output, send, waitFor, getMarks, wasAccepted, wasRejected, close };
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
});
