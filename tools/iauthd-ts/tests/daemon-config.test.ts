/**
 * In-process tests of how the daemon loads its configuration: one parse,
 * and so one set of complaints, per start and per rehash.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { IAuthDaemon } from '../src/iauth.js';

describe('Daemon configuration loading', () => {
  let dir: string;
  let conf: string;
  let out: string[];
  let errors: string[];

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'iauthd-config-load-test-'));
    conf = join(dir, 'test.conf');
    writeFileSync(conf, '#IAUTH POLICY RTAWUwFr\n#IAUTH CACHETIME soon\n');
    out = [];
    errors = [];
    vi.spyOn(console, 'log').mockImplementation((line: string) => { out.push(line); });
    vi.spyOn(console, 'error').mockImplementation((line: string) => { errors.push(line); });
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
  });

  const complaints = () => errors.filter(e => /CACHETIME/.test(e)).length;

  it('complains once at startup and once per rehash, and still shows the config to the ircd', () => {
    const daemon = new IAuthDaemon({ config: conf, debug: false, verbose: false, help: false }) as never as {
      handleStartup(): void;
      handleLine(line: string): void;
    };
    daemon.handleStartup();
    expect(complaints()).toBe(1);
    expect(out).toContain('A * iauthd-ts :2: CACHETIME soon');

    out.length = 0;
    daemon.handleLine('-1 e rehash');
    expect(complaints()).toBe(2);
    expect(out).toContain('A * iauthd-ts :2: CACHETIME soon');
  });

  it('a rehash picks up the changed file', () => {
    const daemon = new IAuthDaemon({ config: conf, debug: false, verbose: false, help: false }) as never as {
      handleStartup(): void;
      handleLine(line: string): void;
    };
    daemon.handleStartup();
    writeFileSync(conf, '#IAUTH POLICY RTAWUwFr\n#IAUTH BLOCKMSG go away\n');
    out.length = 0;
    daemon.handleLine('-1 e rehash');
    expect(out).toContain('A * iauthd-ts :2: BLOCKMSG go away');
    expect(complaints()).toBe(1);
  });
});
