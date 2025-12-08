/**
 * IAuth Daemon - Main implementation
 * Handles communication with Nefarious IRCd and DNSBL lookups
 */
import type { CLIOptions } from './types.js';
export declare class IAuthDaemon {
    private config;
    private configPath;
    private options;
    private clients;
    private dnsblCounters;
    private countPass;
    private countReject;
    private startTime;
    private rl;
    constructor(options: CLIOptions);
    /**
     * Send a message to ircd via stdout
     */
    private send;
    /**
     * Send debug message (prefixed with "> :")
     */
    private debug;
    /**
     * Start the daemon
     */
    start(): void;
    /**
     * Send startup messages to ircd
     */
    private handleStartup;
    /**
     * Send configuration info to ircd
     */
    private sendNewConfig;
    /**
     * Send statistics to ircd
     */
    private sendStats;
    /**
     * Format duration in human-readable form
     */
    private formatDuration;
    /**
     * Handle a line from ircd
     */
    private handleLine;
    /**
     * Handle client introduction (C message)
     */
    private handleClientIntro;
    /**
     * Start DNSBL lookups for a client
     */
    private startDNSBLLookups;
    /**
     * Handle a DNSBL response
     */
    private handleDNSBLResponse;
    /**
     * Check if client processing is complete
     */
    private handleClientUpdate;
    /**
     * Handle Hurry message
     */
    private handleHurry;
    /**
     * Handle authentication (R message)
     */
    private handleAuth;
    /**
     * Handle trusted WEBIRC
     */
    private handleWebIRC;
    /**
     * Accept a client
     */
    private clientPass;
    /**
     * Reject a client
     */
    private clientReject;
    /**
     * Delete a client from tracking
     */
    private deleteClient;
    /**
     * Send mark message
     */
    private sendMark;
    /**
     * Send done message
     */
    private sendDone;
    /**
     * Send kill message
     */
    private sendKill;
}
//# sourceMappingURL=iauth.d.ts.map