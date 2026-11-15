/**
 * Unit tests for configuration parser
 */

import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { writeFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { readConfigFile } from '../src/config.js';

describe('Config Parser', () => {
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

  it('should parse POLICY directive', () => {
    writeFileSync(configPath, '#IAUTH POLICY RTAWUwFr\n');
    const { config } = readConfigFile(configPath);
    expect(config.policy).toBe('RTAWUwFr');
  });

  it('should parse CACHETIME directive', () => {
    writeFileSync(configPath, '#IAUTH CACHETIME 3600\n');
    const { config } = readConfigFile(configPath);
    expect(config.cacheTime).toBe(3600);
  });

  it('CACHETIME 0 means answers are not reused (not the default)', () => {
    writeFileSync(configPath, '#IAUTH CACHETIME 0\n');
    const { config } = readConfigFile(configPath);
    expect(config.cacheTime).toBe(0);
  });

  it('should parse DNSTIMEOUT directive', () => {
    writeFileSync(configPath, '#IAUTH DNSTIMEOUT 10\n');
    const { config } = readConfigFile(configPath);
    expect(config.dnsTimeout).toBe(10);
  });

  it('should parse BLOCKMSG directive', () => {
    writeFileSync(configPath, '#IAUTH BLOCKMSG Your connection has been rejected.\n');
    const { config } = readConfigFile(configPath);
    expect(config.blockMsg).toBe('Your connection has been rejected.');
  });

  it('should parse DEBUG directive', () => {
    writeFileSync(configPath, '#IAUTH DEBUG\n');
    const { config } = readConfigFile(configPath);
    expect(config.debug).toBe(true);
  });

  it('should parse simple DNSBL directive', () => {
    writeFileSync(configPath, '#IAUTH DNSBL server=dnsbl.example.com\n');
    const { config } = readConfigFile(configPath);
    expect(config.dnsbls).toHaveLength(1);
    expect(config.dnsbls[0].server).toBe('dnsbl.example.com');
  });

  it('should parse DNSBL with index', () => {
    writeFileSync(configPath, '#IAUTH DNSBL server=dnsbl.example.com index=2,3,4\n');
    const { config } = readConfigFile(configPath);
    expect(config.dnsbls[0].index).toBe('2,3,4');
  });

  it('should parse DNSBL with bitmask', () => {
    writeFileSync(configPath, '#IAUTH DNSBL server=dnsbl.example.com bitmask=128\n');
    const { config } = readConfigFile(configPath);
    expect(config.dnsbls[0].bitmask).toBe('128');
  });

  it('should parse DNSBL with mark', () => {
    writeFileSync(configPath, '#IAUTH DNSBL server=dnsbl.example.com mark=baduser\n');
    const { config } = readConfigFile(configPath);
    expect(config.dnsbls[0].mark).toBe('baduser');
  });

  it('should parse DNSBL with block=all', () => {
    writeFileSync(configPath, '#IAUTH DNSBL server=dnsbl.example.com block=all\n');
    const { config } = readConfigFile(configPath);
    expect(config.dnsbls[0].block).toBe('all');
  });

  it('should parse DNSBL with block=anonymous', () => {
    writeFileSync(configPath, '#IAUTH DNSBL server=dnsbl.example.com block=anonymous\n');
    const { config } = readConfigFile(configPath);
    expect(config.dnsbls[0].block).toBe('anonymous');
  });

  it('should parse DNSBL with whitelist', () => {
    writeFileSync(configPath, '#IAUTH DNSBL server=whitelist.example.com whitelist\n');
    const { config } = readConfigFile(configPath);
    expect(config.dnsbls[0].whitelist).toBe(true);
  });

  it('should parse DNSBL with class', () => {
    writeFileSync(configPath, '#IAUTH DNSBL server=dnsbl.example.com class=Trusted\n');
    const { config } = readConfigFile(configPath);
    expect(config.dnsbls[0].class).toBe('Trusted');
  });

  it('should parse DNSBL with cachetime override', () => {
    writeFileSync(configPath, '#IAUTH DNSBL server=dnsbl.example.com cachetime=7200\n');
    const { config } = readConfigFile(configPath);
    expect(config.dnsbls[0].cacheTime).toBe(7200);
  });

  it('should parse multiple DNSBL directives', () => {
    writeFileSync(configPath, `
#IAUTH DNSBL server=dnsbl1.example.com index=2,3 mark=bl1
#IAUTH DNSBL server=dnsbl2.example.com index=4,5 mark=bl2 block=anonymous
#IAUTH DNSBL server=whitelist.example.com whitelist
`);
    const { config } = readConfigFile(configPath);
    expect(config.dnsbls).toHaveLength(3);
    expect(config.dnsbls[0].server).toBe('dnsbl1.example.com');
    expect(config.dnsbls[1].server).toBe('dnsbl2.example.com');
    expect(config.dnsbls[1].block).toBe('anonymous');
    expect(config.dnsbls[2].whitelist).toBe(true);
  });

  it('should parse full config with all directives', () => {
    writeFileSync(configPath, `
# This is a comment
#IAUTH POLICY RTAWUwFr
#IAUTH CACHETIME 86400
#IAUTH DNSTIMEOUT 5
#IAUTH BLOCKMSG Sorry! Your connection has been rejected.
#IAUTH DNSBL server=dnsbl.sorbs.net index=2,3,4,5 mark=sorbs block=anonymous
#IAUTH DNSBL server=rbl.efnetrbl.org index=4 mark=tor

# Some other config lines that should be ignored
General {
  name = "test.server";
};
`);
    const { config, configLines } = readConfigFile(configPath);

    expect(config.policy).toBe('RTAWUwFr');
    expect(config.cacheTime).toBe(86400);
    expect(config.dnsTimeout).toBe(5);
    expect(config.blockMsg).toBe('Sorry! Your connection has been rejected.');
    expect(config.dnsbls).toHaveLength(2);
    expect(configLines).toHaveLength(6);
  });

  it('should use defaults when directives are missing', () => {
    writeFileSync(configPath, '# Empty config\n');
    const { config } = readConfigFile(configPath);

    expect(config.policy).toBe('RTAWUwFr');
    expect(config.cacheTime).toBe(86400);
    expect(config.dnsTimeout).toBe(5);
    expect(config.debug).toBe(false);
    expect(config.dnsbls).toHaveLength(0);
  });

  it('should ignore non-IAUTH lines', () => {
    writeFileSync(configPath, `
# Regular comment
General { name = "test"; };
#IAUTH POLICY RTAW
#NOTIAUTHPOLICY test
`);
    const { config } = readConfigFile(configPath);
    expect(config.policy).toBe('RTAW');
  });

  it('should assign incrementing cfgNum to DNSBLs', () => {
    writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH DNSBL server=first.example.com
#IAUTH DNSBL server=second.example.com
#IAUTH DNSBL server=third.example.com
`);
    const { config } = readConfigFile(configPath);
    expect(config.dnsbls[0].cfgNum).toBe(2);
    expect(config.dnsbls[1].cfgNum).toBe(3);
    expect(config.dnsbls[2].cfgNum).toBe(4);
  });

  // A cache time that is not a whole number of seconds is ignored (with a
  // complaint on stderr, which the ircd logs) rather than read as NaN --
  // which never expired -- or as 0.
  describe('bad cache times', () => {
    for (const bad of ['abc', '10x', '1.5', '-', '--5']) {
      it(`ignores cachetime=${bad} on a DNSBL line: the global CACHETIME applies`, () => {
        const err = vi.spyOn(console, 'error').mockImplementation(() => {});
        writeFileSync(configPath, `#IAUTH DNSBL server=dnsbl.example.com cachetime=${bad}\n`);
        const { config } = readConfigFile(configPath);
        expect(config.dnsbls[0].cacheTime).toBeUndefined();
        expect(err).toHaveBeenCalledWith(expect.stringMatching(/cachetime.*dnsbl\.example\.com/i));
        err.mockRestore();
      });
    }

    for (const bad of ['abc', '']) {
      it(`ignores "CACHETIME${bad ? ' ' + bad : ''}": the default applies`, () => {
        const err = vi.spyOn(console, 'error').mockImplementation(() => {});
        writeFileSync(configPath, `#IAUTH CACHETIME${bad ? ' ' + bad : ''}\n`);
        const { config } = readConfigFile(configPath);
        expect(config.cacheTime).toBe(86400);
        expect(err).toHaveBeenCalledWith(expect.stringMatching(/CACHETIME/));
        err.mockRestore();
      });
    }

    // A negative cache time has always meant "not reused" (here and in
    // iauthd.pl): it is read as 0, silently.
    it('a negative cachetime on a DNSBL line or CACHETIME means 0 (not reused), silently', () => {
      const err = vi.spyOn(console, 'error').mockImplementation(() => {});
      writeFileSync(configPath, '#IAUTH CACHETIME -1\n#IAUTH DNSBL server=a.example cachetime=-5\n');
      const { config } = readConfigFile(configPath);
      expect(config.cacheTime).toBe(0);
      expect(config.dnsbls[0].cacheTime).toBe(0);
      expect(err).not.toHaveBeenCalled();
      err.mockRestore();
    });

    it('a good cachetime says nothing', () => {
      const err = vi.spyOn(console, 'error').mockImplementation(() => {});
      writeFileSync(configPath, '#IAUTH CACHETIME 0\n#IAUTH DNSBL server=a.example cachetime=0\n');
      const { config } = readConfigFile(configPath);
      expect(config.cacheTime).toBe(0);
      expect(config.dnsbls[0].cacheTime).toBe(0);
      expect(err).not.toHaveBeenCalled();
      err.mockRestore();
    });
  });

  // A misspelt directive (CACHETIMEOUT for CACHETIME) used to vanish without
  // a trace, leaving the default in force.
  describe('unknown directives', () => {
    it('reports an unknown directive with its line, and otherwise ignores it', () => {
      const err = vi.spyOn(console, 'error').mockImplementation(() => {});
      writeFileSync(configPath, '#IAUTH POLICY RTAWUwFr\n#IAUTH CACHETIMEOUT 21600\n');
      const { config, configLines } = readConfigFile(configPath);
      expect(config.cacheTime).toBe(86400);
      expect(config.policy).toBe('RTAWUwFr');
      expect(configLines).toHaveLength(2);
      expect(err).toHaveBeenCalledTimes(1);
      expect(err).toHaveBeenCalledWith(expect.stringMatching(/unknown #IAUTH directive CACHETIMEOUT.*line 2.*CACHETIMEOUT 21600/));
      err.mockRestore();
    });

    it('says nothing about any directive it knows', () => {
      const err = vi.spyOn(console, 'error').mockImplementation(() => {});
      writeFileSync(configPath, [
        '#IAUTH POLICY RTAWUwFr', '#IAUTH DNSBL server=a.example index=2', '#IAUTH DEBUG',
        '#IAUTH DNSTIMEOUT 5', '#IAUTH BLOCKMSG go away', '#IAUTH CACHETIME 3600',
        '#IAUTH SASLDB /nonexistent/users', '#IAUTH SASLFAILMSG no', '#IAUTH AUTH provider=file path=/nonexistent/users',
        '',
      ].join('\n'));
      readConfigFile(configPath);
      expect(err).not.toHaveBeenCalled();
      err.mockRestore();
    });
  });
});
