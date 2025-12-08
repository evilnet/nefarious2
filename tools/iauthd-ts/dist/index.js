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
import { parseArgs } from 'node:util';
import { IAuthDaemon } from './iauth.js';
const HELP = `
iauthd-ts - IAuth daemon for Nefarious IRCd (TypeScript port)

Usage: iauthd-ts [options] --config=<configfile>

Options:
  -h, --help     Print this message
  -c, --config   Config file to read (required)
  -d, --debug    Turn on debugging in the ircd
  -v, --verbose  Turn on debugging in iauthd
`;
function main() {
    let options;
    try {
        const { values } = parseArgs({
            options: {
                help: { type: 'boolean', short: 'h', default: false },
                config: { type: 'string', short: 'c' },
                debug: { type: 'boolean', short: 'd', default: false },
                verbose: { type: 'boolean', short: 'v', default: false },
            },
            strict: true,
        });
        options = {
            help: values.help ?? false,
            config: values.config ?? '',
            debug: values.debug ?? false,
            verbose: values.verbose ?? false,
        };
    }
    catch (err) {
        console.error(HELP);
        process.exit(1);
    }
    if (options.help || !options.config) {
        console.error(HELP);
        process.exit(options.help ? 0 : 1);
    }
    try {
        const daemon = new IAuthDaemon(options);
        daemon.start();
    }
    catch (err) {
        console.error(`Failed to start iauthd-ts: ${err}`);
        process.exit(1);
    }
}
main();
//# sourceMappingURL=index.js.map