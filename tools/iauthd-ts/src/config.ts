/**
 * Configuration parser for iauthd
 * Reads #IAUTH directives from config files
 */

import { readFileSync } from 'node:fs';
import type { Config, DNSBLConfig } from './types.js';

const DEFAULT_CACHE_TIME = 60 * 60 * 24; // 24 hours
const DEFAULT_DNS_TIMEOUT = 5;
const DEFAULT_BLOCK_MSG = 'Your internet address has been rejected due to reputation (DNSBL).';
const DEFAULT_POLICY = 'RTAWUwFr';

/**
 * Parse a DNSBL configuration line
 * Format: server=dnsbl.sorbs.net index=2,3,4 mark=sorbs block=anonymous
 */
function parseDNSBLConfig(args: string, cfgNum: number): DNSBLConfig {
  const config: DNSBLConfig = {
    cfgNum,
    server: '',
  };

  for (const arg of args.split(/\s+/)) {
    const match = arg.match(/^(\w+)=(.+)$/);
    if (match) {
      const [, key, value] = match;
      switch (key) {
        case 'server':
          config.server = value;
          break;
        case 'index':
          config.index = value;
          break;
        case 'bitmask':
          config.bitmask = value;
          break;
        case 'mark':
          config.mark = value;
          break;
        case 'block':
          if (value === 'all' || value === 'anonymous') {
            config.block = value;
          }
          break;
        case 'class':
          config.class = value;
          break;
        case 'cachetime':
          config.cacheTime = parseInt(value, 10);
          break;
        case 'whitelist':
          config.whitelist = true;
          break;
      }
    } else if (arg === 'whitelist') {
      config.whitelist = true;
    }
  }

  return config;
}

/**
 * Read and parse configuration from a file
 * Looks for lines starting with #IAUTH
 */
export function readConfigFile(filePath: string): { config: Config; configLines: string[] } {
  const config: Config = {
    policy: DEFAULT_POLICY,
    dnsbls: [],
    dnsTimeout: DEFAULT_DNS_TIMEOUT,
    blockMsg: DEFAULT_BLOCK_MSG,
    cacheTime: DEFAULT_CACHE_TIME,
    debug: false,
  };

  const configLines: string[] = [];
  let cfgNum = 0;

  const content = readFileSync(filePath, 'utf-8');

  for (const line of content.split('\n')) {
    const match = line.match(/^#IAUTH\s+(\w+)(?:\s+(.+))?$/);
    if (!match) continue;

    const directive = match[1];
    const args = match[2] || '';
    cfgNum++;

    configLines.push(`${cfgNum}: ${directive} ${args}`);

    switch (directive) {
      case 'POLICY':
        config.policy = args.trim();
        break;

      case 'DNSBL':
        const dnsblConfig = parseDNSBLConfig(args, cfgNum);
        if (dnsblConfig.server) {
          config.dnsbls.push(dnsblConfig);
        }
        break;

      case 'DEBUG':
        config.debug = true;
        break;

      case 'DNSTIMEOUT':
        config.dnsTimeout = parseInt(args.trim(), 10) || DEFAULT_DNS_TIMEOUT;
        break;

      case 'BLOCKMSG':
        config.blockMsg = args.trim();
        break;

      case 'CACHETIME':
        config.cacheTime = parseInt(args.trim(), 10) || DEFAULT_CACHE_TIME;
        break;
    }
  }

  return { config, configLines };
}
