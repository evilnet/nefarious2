/**
 * IAuth Daemon - Main implementation
 * Handles communication with Nefarious IRCd and DNSBL lookups
 */
import { createInterface } from 'node:readline';
import { readConfigFile } from './config.js';
import { reverseIPv4, isIPv4, getCacheEntry, setCacheEntry, getCacheSize, lookupDNSBL, matchesDNSBL, } from './dnsbl.js';
const VERSION = '1.0.0';
export class IAuthDaemon {
    config;
    configPath;
    options;
    clients = new Map();
    dnsblCounters = new Map();
    countPass = 0;
    countReject = 0;
    startTime = Date.now();
    rl = null;
    constructor(options) {
        this.options = options;
        this.configPath = options.config;
        const { config, configLines } = readConfigFile(options.config);
        this.config = config;
        // Initialize DNSBL counters
        for (const dnsbl of this.config.dnsbls) {
            this.dnsblCounters.set(dnsbl.cfgNum, 0);
        }
    }
    /**
     * Send a message to ircd via stdout
     */
    send(message) {
        console.log(message);
    }
    /**
     * Send debug message (prefixed with "> :")
     */
    debug(message) {
        if (this.options.verbose || this.options.debug) {
            this.send(`> :${message}`);
        }
    }
    /**
     * Start the daemon
     */
    start() {
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
    handleStartup() {
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
    sendNewConfig() {
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
    sendStats() {
        const uptime = this.formatDuration(Date.now() - this.startTime);
        const upSince = new Date(this.startTime).toUTCString();
        this.send('s');
        this.send(`S iauthd-ts :Up since ${upSince} (${uptime})`);
        this.send(`S iauthd-ts :Cache size: ${getCacheSize()}`);
        this.send(`S iauthd-ts :Total Passed: ${this.countPass}`);
        this.send(`S iauthd-ts :Total Rejected: ${this.countReject}`);
        for (const dnsbl of this.config.dnsbls) {
            let desc = dnsbl.server;
            if (dnsbl.index)
                desc += ` (${dnsbl.index})`;
            if (dnsbl.bitmask)
                desc += ` (${dnsbl.bitmask})`;
            const count = this.dnsblCounters.get(dnsbl.cfgNum) || 0;
            this.send(`S iauthd-ts :${desc}: ${count}`);
        }
    }
    /**
     * Format duration in human-readable form
     */
    formatDuration(ms) {
        const seconds = Math.floor(ms / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);
        const parts = [];
        if (days > 0)
            parts.push(`${days}d`);
        if (hours % 24 > 0)
            parts.push(`${hours % 24}h`);
        if (minutes % 60 > 0)
            parts.push(`${minutes % 60}m`);
        if (seconds % 60 > 0 || parts.length === 0)
            parts.push(`${seconds % 60}s`);
        return parts.join(' ');
    }
    /**
     * Handle a line from ircd
     */
    handleLine(line) {
        if (!line)
            return;
        const parts = line.split(' ');
        const source = parseInt(parts[0], 10);
        const message = parts[1];
        const args = parts.slice(2).join(' ');
        if (!message)
            return;
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
                    this.sendNewConfig();
                }
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
    handleClientIntro(id, args) {
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
        const client = {
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
    async startDNSBLLookups(client) {
        if (!isIPv4(client.ip)) {
            this.debug(`Unknown IP format: ${client.ip}, probably IPv6... ignoring`);
            return;
        }
        const reversedIp = reverseIPv4(client.ip);
        if (!reversedIp)
            return;
        // Start all lookups concurrently
        const lookupPromises = this.config.dnsbls.map(async (dnsbl) => {
            const query = `${reversedIp}.${dnsbl.server}`;
            client.lookups.set(dnsbl.cfgNum, true); // Mark as pending
            this.debug(`Looking up client ${client.id}: ${query}`);
            // Check cache
            const cacheTime = dnsbl.cacheTime ?? this.config.cacheTime;
            const cached = getCacheEntry(query, cacheTime);
            let results;
            if (cached && cached.result !== null) {
                this.debug(`Found dnsbl cache entry for ${query}`);
                results = cached.result;
            }
            else if (cached) {
                // Cache entry exists but result is null (pending)
                this.debug(`Cache pending... on ${query}`);
                // Wait a bit and retry from cache
                await new Promise((resolve) => setTimeout(resolve, 100));
                const retryCache = getCacheEntry(query, cacheTime);
                results = retryCache?.result ?? [];
            }
            else {
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
    handleDNSBLResponse(client, dnsbl, results) {
        if (results.length === 0)
            return;
        const matched = matchesDNSBL(results, dnsbl);
        if (!matched)
            return;
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
    handleClientUpdate(client) {
        // Count pending lookups
        let pending = 0;
        for (const isPending of client.lookups.values()) {
            if (isPending)
                pending++;
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
                }
                else if (client.block === 'all' ||
                    (client.block === 'anonymous' && !client.account)) {
                    this.clientReject(client, this.config.blockMsg);
                }
                else {
                    this.clientPass(client);
                }
            }
        }
        else {
            this.debug(`Client ${client.id} has ${pending} pending requests`);
        }
    }
    /**
     * Handle Hurry message
     */
    handleHurry(id, classArg) {
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
    handleAuth(id, account) {
        const client = this.clients.get(id);
        if (!client)
            return;
        this.debug(`Client ${id} authed as ${account}`);
        client.account = account;
        this.handleClientUpdate(client);
    }
    /**
     * Handle trusted WEBIRC
     */
    handleWebIRC(id, args) {
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
        const newClient = {
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
    clientPass(client) {
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
    clientReject(client, reason) {
        this.debug(`Rejecting client ${client.id} (${client.ip}): ${reason}`);
        this.sendKill(client, reason);
        this.countReject++;
        this.deleteClient(client.id);
        this.sendStats();
    }
    /**
     * Delete a client from tracking
     */
    deleteClient(id) {
        this.debug('Deleting client from hash tables');
        this.clients.delete(id);
    }
    /**
     * Send mark message
     */
    sendMark(client, markType, markData) {
        if (!markData)
            return;
        this.send(`m ${client.id} ${client.ip} ${client.port} ${markType} ${markData}`);
    }
    /**
     * Send done message
     */
    sendDone(client) {
        if (client.class) {
            this.send(`D ${client.id} ${client.ip} ${client.port} ${client.class}`);
        }
        else {
            this.send(`D ${client.id} ${client.ip} ${client.port}`);
        }
    }
    /**
     * Send kill message
     */
    sendKill(client, reason) {
        this.send(`k ${client.id} ${client.ip} ${client.port} :${reason}`);
    }
}
//# sourceMappingURL=iauth.js.map