/**
 * TypeScript types for iauthd
 */

/** DNSBL configuration entry */
export interface DNSBLConfig {
  /** Config line number for identification */
  cfgNum: number;
  /** DNSBL server hostname (e.g., dnsbl.sorbs.net) */
  server: string;
  /** Match if response equals one of these indices (e.g., "2,3,4") */
  index?: string;
  /** Match if response bitwise-AND with mask is truthy */
  bitmask?: string;
  /** Mark to apply if matched */
  mark?: string;
  /** Block mode: 'all' or 'anonymous' (block unless authenticated) */
  block?: 'all' | 'anonymous';
  /** If true, whitelist this user from all blocks */
  whitelist?: boolean;
  /** Connection class to assign */
  class?: string;
  /** Override cache timeout for this DNSBL */
  cacheTime?: number;
}

/** Main configuration */
export interface Config {
  /** IAuth policy string (e.g., "RTAWUwFr") */
  policy: string;
  /** DNSBL configurations */
  dnsbls: DNSBLConfig[];
  /** DNS lookup timeout in seconds */
  dnsTimeout: number;
  /** Message shown when blocking a client */
  blockMsg: string;
  /** Default cache time in seconds */
  cacheTime: number;
  /** Debug mode */
  debug: boolean;
}

/** Client state during registration */
export interface ClientState {
  /** Client ID from ircd */
  id: number;
  /** Remote IP address */
  ip: string;
  /** Remote port */
  port: number;
  /** Server IP */
  serverIp: string;
  /** Server port */
  serverPort: number;
  /** Whether client is whitelisted */
  whitelist: boolean;
  /** Block mode if any */
  block: 'all' | 'anonymous' | false;
  /** Applied marks */
  marks: Map<string, DNSBLConfig>;
  /** Assigned connection class */
  class?: string;
  /** Whether we've received a Hurry message */
  hurry: boolean;
  /** Pending DNSBL lookups (cfgNum -> pending) */
  lookups: Map<number, boolean>;
  /** Account name if authenticated via SASL/LOC */
  account?: string;
  /** DNSBL hits (cfgNum -> hit) */
  hits: Map<number, boolean>;
}

/** DNSBL cache entry */
export interface CacheEntry {
  /** DNS lookup results (IP addresses) */
  result: string[] | null;
  /** Timestamp when cached */
  ts: number;
}

/** Parsed server message */
export type ServerMessage =
  | { type: 'C'; id: number; remoteIp: string; remotePort: number; localIp: string; localPort: number }
  | { type: 'D'; id: number }
  | { type: 'F'; id: number; fingerprint: string }
  | { type: 'R'; id: number; account: string }
  | { type: 'N'; id: number; hostname: string }
  | { type: 'd'; id: number }
  | { type: 'P'; id: number; password: string }
  | { type: 'U'; id: number; username: string; hostname: string; servername: string; userinfo: string }
  | { type: 'u'; id: number; username?: string }
  | { type: 'n'; id: number; nickname: string }
  | { type: 'H'; id: number; class: string }
  | { type: 'T'; id: number }
  | { type: 'E'; id: number; errorType: string; text: string }
  | { type: 'e'; id: number; event: string; params?: string }
  | { type: 'M'; id: number; servername: string; capacity: number }
  | { type: 'X'; id: number; servername: string; routing: string; reply: string }
  | { type: 'x'; id: number; servername: string; routing: string; message: string }
  | { type: 'W'; id: number; password: string; username: string; hostname: string; ip: string; options?: string }
  | { type: 'w'; id: number; password: string; username: string; hostname: string; ip: string; options?: string }
  | { type: 'unknown'; id: number; raw: string };

/** CLI options */
export interface CLIOptions {
  config: string;
  debug: boolean;
  verbose: boolean;
  help: boolean;
}
