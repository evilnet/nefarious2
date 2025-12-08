#!/usr/bin/env node
/**
 * iauthd-ts - IAuth daemon for Nefarious IRCd
 * TypeScript port of iauthd.pl
 *
 * A DNSBL-based authentication daemon that checks connecting clients
 * against configured DNS blacklists and can block, mark, or whitelist
 * users based on the results.
 *
 * Requirements:
 *   Node.js 18+
 *
 * Installation:
 *   npm install
 *   npm run build
 *
 * Usage:
 *   node dist/index.js -c /path/to/config
 *
 * Configuration:
 *   Config directives begin with #IAUTH and are one per line.
 *   Because configuration begins with #, it can be embedded in ircd.conf.
 *   Syntax is: #IAUTH <directive> <arguments>
 *
 * Configuration directives:
 *
 *   POLICY:
 *     See docs/readme.iauth section on Set Policy Options
 *
 *   DNSTIMEOUT:
 *     Seconds to time out for DNSBL lookups. Default is 5
 *
 *   DNSBL <key=value [key=value..]>
 *     where keys are:
 *       server    - dnsbl server to look up, eg dnsbl.sorbs.net
 *       bitmask   - matches if response is true after being bitwise-and'ed with mask
 *       index     - matches if response is exactly index (comma separated values ok)
 *       class     - assigns the user to the named class
 *       mark      - marks the user with the given mark
 *       block     - all: blocks connection if matched
 *                   anonymous: blocks connection unless SASL authenticated
 *       whitelist - listed users won't be blocked by any RBL
 *       cachetime - Override default cache timeout
 *
 *   DEBUG:
 *     Values greater than 0 turn iauth debugging on in the ircd
 *
 *   BLOCKMSG:
 *     Message shown to users when blocked
 *
 *   CACHETIME:
 *     Default cache time in seconds (default 86400 = 24 hours)
 *
 * Example configuration:
 *
 *   #IAUTH POLICY RTAWUwFr
 *   #IAUTH CACHETIME 86400
 *   #IAUTH BLOCKMSG Sorry! Your connection has been rejected due to poor reputation.
 *   #IAUTH DNSBL server=dnsbl.sorbs.net index=2,3,4,5,6,7,9 mark=sorbs block=anonymous
 *   #IAUTH DNSBL server=dnsbl.dronebl.org index=2,3,5,6,7,8,9,10,13,14,15 mark=dronebl block=anonymous
 *   #IAUTH DNSBL server=rbl.efnetrbl.org index=4 mark=tor
 *   #IAUTH DNSBL server=rbl.efnetrbl.org index=1,2,3,5 mark=efnetrbl block=anonymous
 *
 * ircd.conf:
 *
 *   IAuth {
 *     program = "node" "/path/to/iauthd-ts/dist/index.js" "-v" "-c" "ircd.conf";
 *   };
 *
 * Debugging:
 *   * Oper up first
 *   * Set snomask: /quote mode yournick +s 262144
 */
export {};
//# sourceMappingURL=index.d.ts.map