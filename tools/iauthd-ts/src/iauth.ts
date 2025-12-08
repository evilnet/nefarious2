/**
 * IAuth Daemon - Main implementation
 * Handles communication with Nefarious IRCd and DNSBL lookups
 */

import { createInterface, Interface } from 'node:readline';
import { readConfigFile } from './config.js';
import {
  reverseIPv4,
  isIPv4,
  getCacheEntry,
  setCacheEntry,
  getCacheSize,
  lookupDNSBL,
  matchesDNSBL,
} from './dnsbl.js';
import {
  parseUsersFile,
  usersFileModified,
  decodeSASLPlain,
  authenticatePlain,
  getSupportedMechanisms,
  type UsersDB,
} from './sasl.js';
import type { Config, ClientState, DNSBLConfig, CLIOptions, SASLState } from './types.js';

const VERSION = '1.0.0';

export class IAuthDaemon {
  private config: Config;
  private configPath: string;
  private options: CLIOptions;
  private clients = new Map<number, ClientState>();
  private dnsblCounters = new Map<number, number>();
  private countPass = 0;
  private countReject = 0;
  private countSaslSuccess = 0;
  private countSaslFail = 0;
  private startTime = Date.now();
  private rl: Interface | null = null;
  private usersDb: UsersDB | null = null;

  constructor(options: CLIOptions) {
    this.options = options;
    this.configPath = options.config;
    const { config, configLines } = readConfigFile(options.config);
    this.config = config;

    // Initialize DNSBL counters
    for (const dnsbl of this.config.dnsbls) {
      this.dnsblCounters.set(dnsbl.cfgNum, 0);
    }

    // Load SASL users database if configured
    this.loadUsersDb();
  }

  /**
   * Load or reload the SASL users database
   */
  private loadUsersDb(): void {
    if (this.config.saslUsersFile) {
      this.usersDb = parseUsersFile(this.config.saslUsersFile);
      this.debug(`Loaded ${this.usersDb.users.size} users from ${this.config.saslUsersFile}`);
    }
  }

  /**
   * Check if SASL is enabled (users file configured and has entries)
   */
  private saslEnabled(): boolean {
    return this.usersDb !== null && this.usersDb.users.size > 0;
  }

  /**
   * Send a message to ircd via stdout
   */
  private send(message: string): void {
    console.log(message);
  }

  /**
   * Send debug message (prefixed with "> :")
   */
  private debug(message: string): void {
    if (this.options.verbose || this.options.debug) {
      this.send(`> :${message}`);
    }
  }

  /**
   * Start the daemon
   */
  start(): void {
    this.handleStartup();

    this.rl = createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false,
    });

    this.rl.on('line', (line) => this.handleLine(line));
    this.rl.on('close', () => {
      this.debug('STDIN closed. Shutting down...');
      process.exit(0);
    });
  }

  /**
   * Send startup messages to ircd
   */
  private handleStartup(): void {
    // Request iauth protocol version
    this.send('G 1');

    // Send version
    this.send(`V :Nefarious2 iauthd-ts version ${VERSION}`);

    // Set policy options
    this.send(`O ${this.config.policy}`);

    // Send configuration
    this.sendNewConfig();

    this.debug('Starting up');
    this.sendStats();
  }

  /**
   * Send configuration info to ircd
   */
  private sendNewConfig(): void {
    this.send('a');
    this.send(`A * version :Nefarious iauthd-ts ${VERSION}`);

    const { configLines } = readConfigFile(this.configPath);
    for (const line of configLines) {
      this.send(`A * iauthd-ts :${line}`);
    }
  }

  /**
   * Send statistics to ircd
   */
  private sendStats(): void {
    const uptime = this.formatDuration(Date.now() - this.startTime);
    const upSince = new Date(this.startTime).toUTCString();

    this.send('s');
    this.send(`S iauthd-ts :Up since ${upSince} (${uptime})`);
    this.send(`S iauthd-ts :Cache size: ${getCacheSize()}`);
    this.send(`S iauthd-ts :Total Passed: ${this.countPass}`);
    this.send(`S iauthd-ts :Total Rejected: ${this.countReject}`);

    if (this.saslEnabled()) {
      this.send(`S iauthd-ts :SASL Success: ${this.countSaslSuccess}`);
      this.send(`S iauthd-ts :SASL Failed: ${this.countSaslFail}`);
      this.send(`S iauthd-ts :SASL Users Loaded: ${this.usersDb?.users.size || 0}`);
    }

    for (const dnsbl of this.config.dnsbls) {
      let desc = dnsbl.server;
      if (dnsbl.index) desc += ` (${dnsbl.index})`;
      if (dnsbl.bitmask) desc += ` (${dnsbl.bitmask})`;
      const count = this.dnsblCounters.get(dnsbl.cfgNum) || 0;
      this.send(`S iauthd-ts :${desc}: ${count}`);
    }
  }

  /**
   * Format duration in human-readable form
   */
  private formatDuration(ms: number): string {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    const parts: string[] = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours % 24 > 0) parts.push(`${hours % 24}h`);
    if (minutes % 60 > 0) parts.push(`${minutes % 60}m`);
    if (seconds % 60 > 0 || parts.length === 0) parts.push(`${seconds % 60}s`);

    return parts.join(' ');
  }

  /**
   * Handle a line from ircd
   */
  private handleLine(line: string): void {
    if (!line) return;

    const parts = line.split(' ');
    const source = parseInt(parts[0], 10);
    const message = parts[1];
    const args = parts.slice(2).join(' ');

    if (!message) return;

    switch (message) {
      case 'C': // Client introduction
        this.handleClientIntro(source, args);
        break;

      case 'D': // Client disconnect
        this.debug(`Client ${source} disconnected.`);
        this.deleteClient(source);
        break;

      case 'F': // SSL certificate fingerprint
        // Could be used for certificate-based auth
        break;

      case 'R': // Client authenticated via SASL/LOC
        this.handleAuth(source, args);
        break;

      case 'N': // Hostname received
        break;

      case 'd': // Hostname timeout
        break;

      case 'P': // Client password
        break;

      case 'U': // Client username (full)
        break;

      case 'u': // Client username (short)
        break;

      case 'n': // Client nickname
        break;

      case 'H': // Hurry up
        this.handleHurry(source, args);
        break;

      case 'T': // Client registered
        break;

      case 'E': // Error
        this.debug(`ircd error: ${args}`);
        break;

      case 'e': // Event
        if (args === 'rehash') {
          this.debug('Got a rehash. Rereading config file');
          const { config } = readConfigFile(this.configPath);
          this.config = config;
          this.loadUsersDb();
          this.sendNewConfig();
        }
        break;

      case 'A': // SASL authentication start
        this.handleSASLStart(source, args);
        break;

      case 'a': // SASL authentication continuation
        this.handleSASLContinue(source, args);
        break;

      case 'M': // Server name and capacity
        break;

      case 'X': // Extension query reply
        break;

      case 'x': // Extension query server not linked
        break;

      case 'W': // Untrusted WEBIRC
        this.debug('Got an untrusted WEBIRC attempt. Ignoring.');
        break;

      case 'w': // Trusted WEBIRC
        this.handleWebIRC(source, args);
        break;

      default:
        this.debug(`Got unknown message '${message}' from server`);
    }
  }

  /**
   * Handle client introduction (C message)
   */
  private handleClientIntro(id: number, args: string): void {
    const [ip, portStr, serverIp, serverPortStr] = args.split(' ');
    const port = parseInt(portStr, 10);
    const serverPort = parseInt(serverPortStr, 10);

    if (!ip) {
      this.debug('Got a C without a valid IP. Ignoring');
      return;
    }

    if (this.clients.has(id)) {
      this.debug(`ERROR: Found existing entry for client ${id} (ip=${ip}). Exiting..`);
      process.exit(1);
    }

    this.debug(`Adding new entry for client ${id} (ip=${ip})`);

    const client: ClientState = {
      id,
      ip,
      port,
      serverIp,
      serverPort,
      whitelist: false,
      block: false,
      marks: new Map(),
      hurry: false,
      lookups: new Map(),
      hits: new Map(),
    };

    this.clients.set(id, client);
    this.startDNSBLLookups(client);
  }

  /**
   * Start DNSBL lookups for a client
   */
  private async startDNSBLLookups(client: ClientState): Promise<void> {
    if (!isIPv4(client.ip)) {
      this.debug(`Unknown IP format: ${client.ip}, probably IPv6... ignoring`);
      return;
    }

    const reversedIp = reverseIPv4(client.ip);
    if (!reversedIp) return;

    // Start all lookups concurrently
    const lookupPromises = this.config.dnsbls.map(async (dnsbl) => {
      const query = `${reversedIp}.${dnsbl.server}`;
      client.lookups.set(dnsbl.cfgNum, true); // Mark as pending

      this.debug(`Looking up client ${client.id}: ${query}`);

      // Check cache
      const cacheTime = dnsbl.cacheTime ?? this.config.cacheTime;
      const cached = getCacheEntry(query, cacheTime);

      let results: string[];
      if (cached && cached.result !== null) {
        this.debug(`Found dnsbl cache entry for ${query}`);
        results = cached.result;
      } else if (cached) {
        // Cache entry exists but result is null (pending)
        this.debug(`Cache pending... on ${query}`);
        // Wait a bit and retry from cache
        await new Promise((resolve) => setTimeout(resolve, 100));
        const retryCache = getCacheEntry(query, cacheTime);
        results = retryCache?.result ?? [];
      } else {
        // Start new lookup
        this.debug(`Starting DNS lookup for ${query}`);
        setCacheEntry(query, null); // Mark as pending
        results = await lookupDNSBL(reversedIp, dnsbl.server, this.config.dnsTimeout);
        setCacheEntry(query, results);
      }

      // Process results
      this.handleDNSBLResponse(client, dnsbl, results);

      // Mark lookup as complete
      client.lookups.set(dnsbl.cfgNum, false);

      // Check if we should process the client now
      this.handleClientUpdate(client);
    });

    // Don't await - let lookups happen in background
    Promise.all(lookupPromises).catch((err) => {
      this.debug(`DNSBL lookup error: ${err}`);
    });
  }

  /**
   * Handle a DNSBL response
   */
  private handleDNSBLResponse(client: ClientState, dnsbl: DNSBLConfig, results: string[]): void {
    if (results.length === 0) return;

    const matched = matchesDNSBL(results, dnsbl);
    if (!matched) return;

    this.debug(`client ${client.id} matches ${dnsbl.server} result ${results.join(',')}`);

    // Apply whitelist
    if (dnsbl.whitelist) {
      client.whitelist = true;
    }

    // Apply block
    if (dnsbl.block) {
      client.block = dnsbl.block;
    }

    // Apply class
    if (dnsbl.class) {
      client.class = dnsbl.class;
    }

    // Apply mark
    if (dnsbl.mark) {
      client.marks.set(dnsbl.mark, dnsbl);
    }

    // Record hit
    client.hits.set(dnsbl.cfgNum, true);
  }

  /**
   * Check if client processing is complete
   */
  private handleClientUpdate(client: ClientState): void {
    // Count pending lookups
    let pending = 0;
    for (const isPending of client.lookups.values()) {
      if (isPending) pending++;
    }

    if (client.hurry) {
      this.debug(`Client ${client.id} has Hurry set and ${pending} pending requests`);

      if (pending === 0) {
        // Update counters for hits
        for (const cfgNum of client.hits.keys()) {
          const current = this.dnsblCounters.get(cfgNum) || 0;
          this.dnsblCounters.set(cfgNum, current + 1);
        }
        client.hits.clear();

        // Make decision
        if (client.whitelist) {
          this.clientPass(client);
        } else if (
          client.block === 'all' ||
          (client.block === 'anonymous' && !client.account)
        ) {
          this.clientReject(client, this.config.blockMsg);
        } else {
          this.clientPass(client);
        }
      }
    } else {
      this.debug(`Client ${client.id} has ${pending} pending requests`);
    }
  }

  /**
   * Handle Hurry message
   */
  private handleHurry(id: number, classArg: string): void {
    const client = this.clients.get(id);

    if (!client) {
      this.debug('ERROR: Got a hurry for a client we aren\'t even holding on to!');
      return;
    }

    this.debug(`Handling a hurry on ${id}`);
    client.hurry = true;
    this.handleClientUpdate(client);
  }

  /**
   * Handle authentication (R message)
   */
  private handleAuth(id: number, account: string): void {
    const client = this.clients.get(id);
    if (!client) return;

    this.debug(`Client ${id} authed as ${account}`);
    client.account = account;
    this.handleClientUpdate(client);
  }

  /**
   * Handle trusted WEBIRC
   */
  private handleWebIRC(id: number, args: string): void {
    const parts = args.split(' ');
    const [password, username, hostname, newIp] = parts;

    this.debug(`Got a w line: ${id} - pass=<notshown>, user=${username}, host=${hostname}, ip=${newIp}`);

    const client = this.clients.get(id);
    if (!client) {
      this.debug('Got a webirc for a client we don\'t know about? Ignored.');
      return;
    }

    // Save state
    const wasHurry = client.hurry;

    // Delete and recreate with new IP
    this.clients.delete(id);

    const newClient: ClientState = {
      id,
      ip: newIp,
      port: client.port,
      serverIp: client.serverIp,
      serverPort: client.serverPort,
      whitelist: false,
      block: false,
      marks: new Map(),
      hurry: wasHurry,
      lookups: new Map(),
      hits: new Map(),
    };

    this.clients.set(id, newClient);
    this.startDNSBLLookups(newClient);
  }

  /**
   * Accept a client
   */
  private clientPass(client: ClientState): void {
    this.debug(`Passing client ${client.id} (${client.ip})`);

    // Send marks
    for (const mark of client.marks.keys()) {
      this.sendMark(client, 'MARK', mark);
    }

    // Send done
    this.sendDone(client);
    this.countPass++;
    this.deleteClient(client.id);
    this.sendStats();
  }

  /**
   * Reject a client
   */
  private clientReject(client: ClientState, reason: string): void {
    this.debug(`Rejecting client ${client.id} (${client.ip}): ${reason}`);
    this.sendKill(client, reason);
    this.countReject++;
    this.deleteClient(client.id);
    this.sendStats();
  }

  /**
   * Delete a client from tracking
   */
  private deleteClient(id: number): void {
    this.debug('Deleting client from hash tables');
    this.clients.delete(id);
  }

  /**
   * Send mark message
   */
  private sendMark(client: ClientState, markType: string, markData: string): void {
    if (!markData) return;
    this.send(`m ${client.id} ${client.ip} ${client.port} ${markType} ${markData}`);
  }

  /**
   * Send done message
   */
  private sendDone(client: ClientState): void {
    if (client.class) {
      this.send(`D ${client.id} ${client.ip} ${client.port} ${client.class}`);
    } else {
      this.send(`D ${client.id} ${client.ip} ${client.port}`);
    }
  }

  /**
   * Send kill message
   */
  private sendKill(client: ClientState, reason: string): void {
    this.send(`k ${client.id} ${client.ip} ${client.port} :${reason}`);
  }

  // ==================== SASL Authentication ====================

  /**
   * Handle SASL authentication start (A message from IRCd)
   * Format: A <id> <ip> <port> <mechanism> [:<certfp>]
   * Or for host info: A <id> <ip> <port> H :<user@host:ip>
   */
  private handleSASLStart(id: number, args: string): void {
    if (!this.saslEnabled()) {
      this.debug(`SASL not enabled, ignoring A message for ${id}`);
      this.sendSASLFail(id);
      return;
    }

    // Reload users file if modified
    if (this.usersDb && usersFileModified(this.usersDb)) {
      this.loadUsersDb();
    }

    // Parse: <ip> <port> <mechanism_or_H> [:<extra>]
    const spaceIdx = args.indexOf(' ');
    if (spaceIdx === -1) {
      this.debug(`Invalid SASL A message format: ${args}`);
      return;
    }

    const ip = args.substring(0, spaceIdx);
    const rest = args.substring(spaceIdx + 1);

    const parts = rest.split(' ');
    if (parts.length < 2) {
      this.debug(`Invalid SASL A message format: ${args}`);
      return;
    }

    const port = parseInt(parts[0], 10);
    const mechanismOrType = parts[1];

    // Get or create client state
    let client = this.clients.get(id);
    if (!client) {
      // Create minimal client state for SASL-only handling
      client = {
        id,
        ip,
        port,
        serverIp: '',
        serverPort: 0,
        whitelist: false,
        block: false,
        marks: new Map(),
        hurry: false,
        lookups: new Map(),
        hits: new Map(),
        sasl: { started: false },
      };
      this.clients.set(id, client);
    }

    if (!client.sasl) {
      client.sasl = { started: false };
    }

    // Check if this is host info (H) or mechanism start (S)
    if (mechanismOrType === 'H') {
      // Host info: A <id> <ip> <port> H :<user@host:ip>
      const colonIdx = rest.indexOf(':');
      if (colonIdx !== -1) {
        client.sasl.hostInfo = rest.substring(colonIdx + 1);
        this.debug(`SASL host info for ${id}: ${client.sasl.hostInfo}`);
      }
      return;
    }

    if (mechanismOrType === 'S') {
      // Mechanism start: A <id> <ip> <port> S <mechanism> [:<certfp>]
      // Format from IRCd: S <mechanism> or S <mechanism> :<certfp>
      const mechanismPart = parts.slice(2).join(' ');
      const colonIdx = mechanismPart.indexOf(':');

      let mechanism: string;
      let certfp: string | undefined;

      if (colonIdx !== -1) {
        mechanism = mechanismPart.substring(0, colonIdx).trim();
        certfp = mechanismPart.substring(colonIdx + 1).trim();
      } else {
        mechanism = mechanismPart.trim();
      }

      this.debug(`SASL start for ${id}: mechanism=${mechanism}, certfp=${certfp || 'none'}`);

      client.sasl.mechanism = mechanism;
      client.sasl.certfp = certfp;
      client.sasl.started = true;

      // Check if mechanism is supported
      const supported = getSupportedMechanisms();
      if (!supported.includes(mechanism.toUpperCase())) {
        this.debug(`Unsupported SASL mechanism: ${mechanism}`);
        this.sendSASLMechs(id, supported);
        return;
      }

      // For PLAIN mechanism, we need to wait for the data in the C message
      // Send an empty challenge to request the credentials
      if (mechanism.toUpperCase() === 'PLAIN') {
        this.sendSASLChallenge(id, '+');
      }
      return;
    }

    this.debug(`Unknown SASL A message type: ${mechanismOrType}`);
  }

  /**
   * Handle SASL authentication continuation (a message from IRCd)
   * Format: a <id> <ip> <port> :<base64_data>
   */
  private handleSASLContinue(id: number, args: string): void {
    if (!this.saslEnabled()) {
      this.sendSASLFail(id);
      return;
    }

    const client = this.clients.get(id);
    if (!client || !client.sasl) {
      this.debug(`SASL continue for unknown client ${id}`);
      this.sendSASLFail(id);
      return;
    }

    // Parse: <ip> <port> :<data>
    const colonIdx = args.indexOf(':');
    if (colonIdx === -1) {
      this.debug(`Invalid SASL a message format: ${args}`);
      this.sendSASLFail(id);
      return;
    }

    const data = args.substring(colonIdx + 1);

    if (client.sasl.mechanism?.toUpperCase() === 'PLAIN') {
      this.handleSASLPlain(client, data);
    } else {
      this.debug(`Unhandled SASL mechanism: ${client.sasl.mechanism}`);
      this.sendSASLFail(id);
    }
  }

  /**
   * Handle SASL PLAIN authentication
   */
  private handleSASLPlain(client: ClientState, base64Data: string): void {
    const decoded = decodeSASLPlain(base64Data);

    if (!decoded) {
      this.debug(`Failed to decode SASL PLAIN data for ${client.id}`);
      this.sendSASLFail(client.id);
      this.countSaslFail++;
      return;
    }

    this.debug(`SASL PLAIN auth attempt for ${client.id}: authcid=${decoded.authcid}`);

    const account = authenticatePlain(this.usersDb!, decoded.authcid, decoded.password);

    if (account) {
      this.debug(`SASL PLAIN auth success for ${client.id}: account=${account}`);
      client.account = account;
      this.sendSASLSuccess(client.id, account);
      this.countSaslSuccess++;
    } else {
      this.debug(`SASL PLAIN auth failed for ${client.id}`);
      this.sendSASLFail(client.id);
      this.countSaslFail++;
    }
  }

  /**
   * Send SASL challenge to client
   * Format: c <id> <ip> <port> :<challenge>
   */
  private sendSASLChallenge(id: number, challenge: string): void {
    const client = this.clients.get(id);
    if (client) {
      this.send(`c ${id} ${client.ip} ${client.port} :${challenge}`);
    }
  }

  /**
   * Send SASL login success
   * Format: L <id> <ip> <port> <account>
   */
  private sendSASLSuccess(id: number, account: string): void {
    const client = this.clients.get(id);
    if (client) {
      this.send(`L ${id} ${client.ip} ${client.port} ${account}`);
    }
  }

  /**
   * Send SASL authentication failed
   * Format: f <id> <ip> <port>
   */
  private sendSASLFail(id: number): void {
    const client = this.clients.get(id);
    if (client) {
      this.send(`f ${id} ${client.ip} ${client.port}`);
    } else {
      // Client may not exist yet, send with dummy values
      this.send(`f ${id} 0.0.0.0 0`);
    }
  }

  /**
   * Send SASL available mechanisms
   * Format: l <id> <ip> <port> :<mechanisms>
   */
  private sendSASLMechs(id: number, mechanisms: string[]): void {
    const client = this.clients.get(id);
    if (client) {
      this.send(`l ${id} ${client.ip} ${client.port} :${mechanisms.join(',')}`);
    }
  }
}
