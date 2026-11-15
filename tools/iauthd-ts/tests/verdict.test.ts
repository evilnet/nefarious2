/**
 * In-process tests of a client's pending-lookup accounting: the verdict
 * (D = pass, k = kill) comes once, after the last configured list.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { promises as dnsPromises } from 'node:dns';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { IAuthDaemon } from '../src/iauth.js';
import { setCacheEntry } from '../src/dnsbl.js';

/** Let every pending promise continuation run */
const settle = () => new Promise(r => setImmediate(r));

describe('Verdict accounting', () => {
  let dir: string;
  let out: string[];
  let daemon: { handleLine(line: string): void; clients: Map<number, { lookups: Map<number, boolean> }> };
  /** Answers for the slow list, released by the test */
  let release: Map<string, (r: string[]) => void>;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'iauthd-verdict-test-'));
    const conf = join(dir, 'test.conf');
    writeFileSync(conf, [
      '#IAUTH POLICY RTAWUwFr',
      '#IAUTH DNSBL server=cached.dnsbl index=2 block=all',
      '#IAUTH DNSBL server=slow.dnsbl index=2 block=all',
      '',
    ].join('\n'));
    out = [];
    vi.spyOn(console, 'log').mockImplementation((line: string) => { out.push(line); });
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    release = new Map();
    vi.spyOn(dnsPromises, 'resolve4').mockImplementation(((name: string) =>
      new Promise<string[]>(resolve => release.set(name, resolve))) as never);
    daemon = new IAuthDaemon({ config: conf, debug: false, verbose: false, help: false }) as never;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
  });

  const verdicts = (id: number) => out.filter(l => new RegExp(`^[Dk] ${id} `).test(l));

  it('every list is pending as soon as the client is introduced', () => {
    setCacheEntry('1.0.7.10.cached.dnsbl', [], 3600);
    daemon.handleLine('70 C 10.7.0.1 10070 10.0.0.1 6667');
    expect([...daemon.clients.get(70)!.lookups.values()]).toEqual([true, true]);
  });

  it('a hurried client with one answer cached waits for the other list, then gets one verdict', async () => {
    setCacheEntry('2.0.7.10.cached.dnsbl', [], 3600);       // clean, at hand
    daemon.handleLine('71 C 10.7.0.2 10071 10.0.0.1 6667');
    daemon.handleLine('71 H Users');
    await settle();

    expect(verdicts(71)).toEqual([]);                        // slow.dnsbl not answered yet
    expect([...daemon.clients.get(71)!.lookups.values()]).toEqual([false, true]);

    release.get('2.0.7.10.slow.dnsbl')!(['127.0.0.2']);
    await settle();
    expect(verdicts(71)).toEqual(['k 71 10.7.0.2 10071 :Your internet address has been rejected due to reputation (DNSBL).']);
  });

  it('a client hurried before a trusted WEBIRC waits for every list on the new address', async () => {
    setCacheEntry('4.0.7.10.cached.dnsbl', [], 3600);       // the real address: one list at hand
    daemon.handleLine('72 C 10.7.0.3 10072 10.0.0.1 6667');
    daemon.handleLine('72 H Users');
    daemon.handleLine('72 w pass user host.example 10.7.0.4');
    await settle();

    expect(verdicts(72)).toEqual([]);
    release.get('3.0.7.10.cached.dnsbl')?.([]);             // the gateway's answers count for nothing
    release.get('3.0.7.10.slow.dnsbl')?.([]);
    await settle();
    expect(verdicts(72)).toEqual([]);

    release.get('4.0.7.10.slow.dnsbl')!(['127.0.0.2']);
    await settle();
    expect(verdicts(72)).toEqual(['k 72 10.7.0.4 10072 :Your internet address has been rejected due to reputation (DNSBL).']);
  });
});
