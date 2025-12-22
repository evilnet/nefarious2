/**
 * Integration tests for IAuth protocol
 * Tests the full protocol communication by spawning the daemon
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { spawn, ChildProcess } from 'node:child_process';
import { writeFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createInterface } from 'node:readline';

interface IAuthTestHarness {
  process: ChildProcess;
  output: string[];
  send: (line: string) => void;
  waitForOutput: (pattern: RegExp, timeout?: number) => Promise<string>;
  waitForLines: (count: number, timeout?: number) => Promise<string[]>;
  close: () => Promise<void>;
}

async function createTestHarness(configPath: string): Promise<IAuthTestHarness> {
  const output: string[] = [];

  const proc = spawn('npx', ['tsx', 'src/index.ts', '-v', '-c', configPath], {
    cwd: join(import.meta.dirname, '..'),
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  const rl = createInterface({ input: proc.stdout! });

  rl.on('line', (line) => {
    output.push(line);
  });

  // Also capture stderr for debugging
  proc.stderr?.on('data', (data) => {
    console.error('stderr:', data.toString());
  });

  const send = (line: string) => {
    proc.stdin!.write(line + '\n');
  };

  const waitForOutput = (pattern: RegExp, timeout = 5000): Promise<string> => {
    return new Promise((resolve, reject) => {
      // First check existing output
      for (const line of output) {
        if (pattern.test(line)) {
          resolve(line);
          return;
        }
      }

      const startLen = output.length;
      const checkInterval = setInterval(() => {
        for (let i = startLen; i < output.length; i++) {
          if (pattern.test(output[i])) {
            clearInterval(checkInterval);
            clearTimeout(timeoutId);
            resolve(output[i]);
            return;
          }
        }
      }, 10);

      const timeoutId = setTimeout(() => {
        clearInterval(checkInterval);
        reject(new Error(`Timeout waiting for pattern: ${pattern}`));
      }, timeout);
    });
  };

  const waitForLines = (count: number, timeout = 5000): Promise<string[]> => {
    return new Promise((resolve, reject) => {
      const startLen = output.length;
      const checkInterval = setInterval(() => {
        if (output.length >= startLen + count) {
          clearInterval(checkInterval);
          clearTimeout(timeoutId);
          resolve(output.slice(startLen, startLen + count));
        }
      }, 10);

      const timeoutId = setTimeout(() => {
        clearInterval(checkInterval);
        resolve(output.slice(startLen)); // Return what we have
      }, timeout);
    });
  };

  const close = (): Promise<void> => {
    return new Promise((resolve) => {
      proc.on('close', () => resolve());
      proc.stdin!.end();
      setTimeout(() => {
        proc.kill('SIGTERM');
        resolve();
      }, 1000);
    });
  };

  // Wait for startup - wait for stats output which comes last
  await waitForOutput(/^S iauthd-ts/);
  // Small delay to ensure all startup output is captured
  await new Promise(r => setTimeout(r, 100));

  return { process: proc, output, send, waitForOutput, waitForLines, close };
}

describe('IAuth Protocol Integration', () => {
  let tempDir: string;
  let configPath: string;

  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'iauthd-test-'));
    configPath = join(tempDir, 'test.conf');
  });

  afterAll(() => {
    try {
      unlinkSync(configPath);
    } catch {}
  });

  describe('Startup Messages', () => {
    let harness: IAuthTestHarness;

    beforeEach(async () => {
      writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH CACHETIME 3600
#IAUTH BLOCKMSG Test rejection message
`);
      harness = await createTestHarness(configPath);
    });

    afterEach(async () => {
      await harness?.close();
    });

    it('should send G (protocol version request) on startup', () => {
      expect(harness.output).toContain('G 1');
    });

    it('should send V (version) on startup', () => {
      const versionLine = harness.output.find(l => l.startsWith('V :'));
      expect(versionLine).toBeDefined();
      expect(versionLine).toContain('iauthd-ts');
    });

    it('should send O (policy) on startup', () => {
      expect(harness.output).toContain('O RTAWUwFr');
    });

    it('should send a (new config) on startup', () => {
      expect(harness.output).toContain('a');
    });

    it('should send A (config info) lines on startup', () => {
      const configLines = harness.output.filter(l => l.startsWith('A *'));
      expect(configLines.length).toBeGreaterThan(0);
    });

    it('should send s (stats start) on startup', () => {
      expect(harness.output).toContain('s');
    });

    it('should send S (stats) lines on startup', () => {
      const statsLines = harness.output.filter(l => l.startsWith('S '));
      expect(statsLines.length).toBeGreaterThan(0);
    });
  });

  describe('Client Handling', () => {
    let harness: IAuthTestHarness;

    beforeEach(async () => {
      // Config with no DNSBLs - clients should pass immediately
      writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
`);
      harness = await createTestHarness(configPath);
    });

    afterEach(async () => {
      await harness?.close();
    });

    it('should accept a client with no DNSBLs configured', async () => {
      harness.send('0 C 192.168.1.10 12345 10.0.0.1 6667');
      harness.send('0 H Users');

      const doneLine = await harness.waitForOutput(/^D 0 192\.168\.1\.10 12345/);
      expect(doneLine).toBeDefined();
    });

    it('should handle client disconnect', async () => {
      harness.send('0 C 192.168.1.10 12345 10.0.0.1 6667');
      harness.send('0 D');

      // Should see debug message about disconnect
      await harness.waitForOutput(/disconnected/i, 1000).catch(() => {});
      // No error should occur
    });

    it('should handle multiple concurrent clients', async () => {
      harness.send('0 C 192.168.1.10 12345 10.0.0.1 6667');
      harness.send('1 C 192.168.1.11 12346 10.0.0.1 6667');
      harness.send('2 C 192.168.1.12 12347 10.0.0.1 6667');

      harness.send('0 H Users');
      harness.send('1 H Users');
      harness.send('2 H Users');

      // All three should be accepted (longer timeout for concurrent processing)
      await harness.waitForOutput(/^D 0/, 10000);
      await harness.waitForOutput(/^D 1/, 10000);
      await harness.waitForOutput(/^D 2/, 10000);
    }, 15000);
  });

  describe('SASL/LOC Authentication', () => {
    let harness: IAuthTestHarness;

    beforeEach(async () => {
      // Config that blocks anonymous but allows authenticated
      writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH BLOCKMSG Blocked for testing
`);
      harness = await createTestHarness(configPath);
    });

    afterEach(async () => {
      await harness?.close();
    });

    it('should track authenticated account', async () => {
      harness.send('0 C 192.168.1.10 12345 10.0.0.1 6667');
      harness.send('0 R testuser');
      harness.send('0 H Users');

      // Should see debug about auth
      const authLine = await harness.waitForOutput(/authed as testuser/i);
      expect(authLine).toBeDefined();
    });
  });

  describe('SASL PLAIN Authentication', () => {
    let harness: IAuthTestHarness;
    let usersPath: string;

    beforeEach(async () => {
      // Create users file with test user (password: testpass)
      usersPath = join(tempDir, 'users');
      // Plain text password for testing
      writeFileSync(usersPath, 'testuser:testpass\n');

      // Config with SASL enabled (S in policy) and users file
      writeFileSync(configPath, `
#IAUTH POLICY SRTAWUwFr
#IAUTH SASLDB ${usersPath}
#IAUTH SASLFAILMSG Authentication failed
`);
      harness = await createTestHarness(configPath);
    });

    afterEach(async () => {
      await harness?.close();
      try {
        unlinkSync(usersPath);
      } catch {}
    });

    it('should respond with challenge when SASL PLAIN is requested', async () => {
      // IRCd introduces a client
      harness.send('0 C 192.168.1.10 12345 10.0.0.1 6667');

      // IRCd sends SASL start with mechanism
      // Format: <id> A S :<mechanism>
      harness.send('0 A S :PLAIN');

      // iauthd should respond with empty challenge ('+' means ready)
      // Format: c <id> <ip> <port> :<challenge>
      const challengeLine = await harness.waitForOutput(/^c 0 192\.168\.1\.10 12345 :\+$/);
      expect(challengeLine).toBeDefined();
    });

    it('should send L and Z messages on successful authentication', async () => {
      harness.send('0 C 192.168.1.10 12345 10.0.0.1 6667');
      harness.send('0 A S :PLAIN');

      await harness.waitForOutput(/^c 0/);

      // Send SASL continuation with credentials
      // Format: <id> a :<base64_data>
      // Base64 of "\0testuser\0testpass" (SASL PLAIN format)
      const credentials = Buffer.from('\0testuser\0testpass').toString('base64');
      harness.send(`0 a :${credentials}`);

      // iauthd should respond with L (login success) then Z (SASL complete)
      // Format: L <id> <ip> <port> <account>
      const loginLine = await harness.waitForOutput(/^L 0 192\.168\.1\.10 12345 testuser$/);
      expect(loginLine).toBeDefined();

      // Format: Z <id> <ip> <port>
      const completeLine = await harness.waitForOutput(/^Z 0 192\.168\.1\.10 12345$/);
      expect(completeLine).toBeDefined();
    });

    it('should send f message on failed authentication', async () => {
      harness.send('0 C 192.168.1.10 12345 10.0.0.1 6667');
      harness.send('0 A S :PLAIN');

      await harness.waitForOutput(/^c 0/);

      // Send wrong credentials
      const credentials = Buffer.from('\0testuser\0wrongpass').toString('base64');
      harness.send(`0 a :${credentials}`);

      // iauthd should respond with f (auth failed)
      // Format: f <id> <ip> <port>
      const failLine = await harness.waitForOutput(/^f 0 192\.168\.1\.10 12345$/);
      expect(failLine).toBeDefined();
    });

    it('should handle SASL host info message', async () => {
      harness.send('0 C 192.168.1.10 12345 10.0.0.1 6667');

      // IRCd sends host info with SASL start
      // Format: <id> A H :<user@host:ip>
      harness.send('0 A H :user@testhost.example.com:192.168.1.10');

      // Should see debug about host info
      const hostLine = await harness.waitForOutput(/SASL host info.*testhost/i);
      expect(hostLine).toBeDefined();
    });

    it('should handle mechanism with certfp', async () => {
      harness.send('0 C 192.168.1.10 12345 10.0.0.1 6667');

      // Format with certfp: <id> A S <mechanism> :<certfp>
      harness.send('0 A S PLAIN :abc123fingerprint');

      // Should respond with challenge
      const challengeLine = await harness.waitForOutput(/^c 0/);
      expect(challengeLine).toBeDefined();
    });

    it('should send mechanism list for unsupported mechanism', async () => {
      harness.send('0 C 192.168.1.10 12345 10.0.0.1 6667');

      // Request unsupported mechanism
      harness.send('0 A S :EXTERNAL');

      // Should respond with mechanism list
      // Format: l <id> <ip> <port> :<mechanisms>
      const mechLine = await harness.waitForOutput(/^l 0 192\.168\.1\.10 12345 :PLAIN$/);
      expect(mechLine).toBeDefined();
    });

    it('should complete full SASL flow then accept client', async () => {
      harness.send('0 C 192.168.1.10 12345 10.0.0.1 6667');
      harness.send('0 A S :PLAIN');

      await harness.waitForOutput(/^c 0/);

      const credentials = Buffer.from('\0testuser\0testpass').toString('base64');
      harness.send(`0 a :${credentials}`);

      await harness.waitForOutput(/^L 0/);
      await harness.waitForOutput(/^Z 0/);

      // Now hurry up to finish connection
      harness.send('0 H Users');

      // Should accept the client with D message
      const doneLine = await harness.waitForOutput(/^D 0 192\.168\.1\.10 12345/);
      expect(doneLine).toBeDefined();
    });
  });

  describe('WEBIRC Handling', () => {
    let harness: IAuthTestHarness;

    beforeEach(async () => {
      writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
`);
      harness = await createTestHarness(configPath);
    });

    afterEach(async () => {
      await harness?.close();
    });

    it('should ignore untrusted WEBIRC (capital W)', async () => {
      harness.send('0 C 10.0.0.100 12345 10.0.0.1 6667');
      harness.send('0 W password user host.example.com 192.168.1.10');

      await harness.waitForOutput(/untrusted WEBIRC/i);
    });

    it('should process trusted WEBIRC (lowercase w)', async () => {
      harness.send('0 C 10.0.0.100 12345 10.0.0.1 6667');
      harness.send('0 w password user host.example.com 192.168.1.10');
      harness.send('0 H Users');

      // Should accept with new IP
      const doneLine = await harness.waitForOutput(/^D 0 192\.168\.1\.10/);
      expect(doneLine).toBeDefined();
    });
  });

  describe('Error Handling', () => {
    let harness: IAuthTestHarness;

    beforeEach(async () => {
      writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
`);
      harness = await createTestHarness(configPath);
    });

    afterEach(async () => {
      await harness?.close();
    });

    it('should handle malformed client intro gracefully', async () => {
      harness.send('0 C');  // Missing IP and ports
      // Should not crash, might log an error
      await new Promise(r => setTimeout(r, 100));
      expect(harness.process.exitCode).toBeNull(); // Still running
    });

    it('should handle unknown message types gracefully', async () => {
      harness.send('0 Z some unknown message');
      await harness.waitForOutput(/unknown message/i, 1000).catch(() => {});
      expect(harness.process.exitCode).toBeNull(); // Still running
    });

    it('should handle Hurry for unknown client gracefully', async () => {
      harness.send('99 H Users');  // Client 99 was never introduced
      await harness.waitForOutput(/ERROR.*hurry/i, 1000).catch(() => {});
      expect(harness.process.exitCode).toBeNull(); // Still running
    });
  });

  describe('IPv6 Handling', () => {
    let harness: IAuthTestHarness;

    beforeEach(async () => {
      writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH DNSBL server=dnsbl.example.com index=2
`);
      harness = await createTestHarness(configPath);
    });

    afterEach(async () => {
      await harness?.close();
    });

    it('should skip DNSBL lookups for IPv6 and accept client', async () => {
      harness.send('0 C 2001:db8::1 12345 ::1 6667');
      harness.send('0 H Users');

      // Should accept (IPv6 skips DNSBL lookups)
      const doneLine = await harness.waitForOutput(/^D 0/);
      expect(doneLine).toBeDefined();
    });
  });
});
