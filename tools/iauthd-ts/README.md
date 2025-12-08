# iauthd-ts

A TypeScript implementation of an IAuth daemon for Nefarious IRCd. This daemon performs real-time DNS-based blacklist (DNSBL) lookups on connecting clients and can block, mark, or whitelist users based on the results.

This is a port of the original Perl `iauthd.pl` to TypeScript/Node.js.

## Features

- **DNSBL Lookups**: Check connecting clients against multiple DNS blacklists
- **Flexible Matching**: Match by index value or bitmask
- **Caching**: DNS results are cached to reduce lookup overhead
- **SASL Authentication**: Handle SASL PLAIN authentication directly in IAuth (no services required)
- **SASL/LOC Support**: Exempt authenticated users from blocks
- **WEBIRC Support**: Re-check real IP for trusted proxy connections
- **Marking**: Tag users with marks visible to operators
- **Class Assignment**: Assign users to connection classes based on DNSBL results
- **Whitelisting**: Exempt users matching certain DNSBLs from all blocks

## How It Works

```
┌─────────────┐     stdin/stdout      ┌─────────────┐
│  Nefarious  │ ◄──────────────────► │  iauthd-ts  │
│    IRCd     │    IAuth Protocol     │             │
└─────────────┘                       └──────┬──────┘
                                             │
                                             │ DNS queries
                                             ▼
                                      ┌─────────────┐
                                      │   DNSBL     │
                                      │  Servers    │
                                      └─────────────┘
```

1. **Client Connects**: IRCd sends client info to iauthd-ts via the IAuth protocol
2. **DNSBL Lookup**: iauthd-ts reverses the client IP and queries configured DNSBLs
3. **Result Processing**: Responses are checked against configured index/bitmask rules
4. **Decision**: Client is accepted (with optional marks/class) or rejected
5. **Response**: iauthd-ts sends the decision back to IRCd

### IAuth Protocol

iauthd-ts communicates with Nefarious via stdin/stdout using the IAuth protocol:

| Direction | Message | Description |
|-----------|---------|-------------|
| IRCd → iauthd | `C <id> <ip> <port> <serverip> <serverport>` | Client introduction |
| IRCd → iauthd | `H <id> <class>` | Hurry up (registration timeout approaching) |
| IRCd → iauthd | `R <id> <account>` | Client authenticated via SASL/LOC |
| IRCd → iauthd | `D <id>` | Client disconnected |
| iauthd → IRCd | `D <id> <ip> <port> [class]` | Accept client |
| iauthd → IRCd | `k <id> <ip> <port> :<reason>` | Reject client |
| iauthd → IRCd | `m <id> <ip> <port> MARK <data>` | Mark client |
| IRCd → iauthd | `A <id> <ip> <port> S <mechanism> [:<certfp>]` | SASL auth start |
| IRCd → iauthd | `A <id> <ip> <port> H :<user@host:ip>` | SASL host info |
| IRCd → iauthd | `a <id> <ip> <port> :<data>` | SASL auth data |
| iauthd → IRCd | `c <id> <ip> <port> :<challenge>` | SASL challenge |
| iauthd → IRCd | `L <id> <ip> <port> <account>` | SASL login success |
| iauthd → IRCd | `f <id> <ip> <port>` | SASL auth failed |
| iauthd → IRCd | `l <id> <ip> <port> :<mechanisms>` | SASL mechanism list |
| iauthd → IRCd | `Z <id> <ip> <port>` | SASL auth complete |

## Requirements

- Node.js 18 or later
- npm

## Installation

### From Source

```bash
cd tools/iauthd-ts
npm install
npm run build
```

### Docker

iauthd-ts is automatically built as part of the Nefarious Docker image. The compiled files are located at `/home/nefarious/ircd/iauthd-ts/`.

## Configuration

iauthd-ts reads configuration from `#IAUTH` directives in the config file. These can be embedded in your `ircd.conf` since IRCd ignores lines starting with `#`.

### Directives

#### POLICY
```
#IAUTH POLICY RTAWUwFr
```
Sets the IAuth policy flags. See `doc/readme.iauth` for details.

#### DNSTIMEOUT
```
#IAUTH DNSTIMEOUT 5
```
Seconds to wait for DNSBL lookups. Default: 5

#### CACHETIME
```
#IAUTH CACHETIME 86400
```
Seconds to cache DNSBL results. Default: 86400 (24 hours)

#### BLOCKMSG
```
#IAUTH BLOCKMSG Sorry! Your connection has been rejected due to poor reputation.
```
Message shown to blocked users.

#### DEBUG
```
#IAUTH DEBUG
```
Enable debug output.

#### SASLDB
```
#IAUTH SASLDB /path/to/users
```
Path to the SASL users file. When set, iauthd-ts will handle SASL PLAIN authentication directly instead of routing to services. The policy must include 'S' for this to work.

#### SASLFAILMSG
```
#IAUTH SASLFAILMSG Authentication failed
```
Message shown when SASL authentication fails.

#### DNSBL
```
#IAUTH DNSBL server=<server> [options...]
```

Options:
| Option | Description |
|--------|-------------|
| `server=<host>` | DNSBL server hostname (required) |
| `index=<n,n,...>` | Match if response equals any of these values |
| `bitmask=<n>` | Match if response AND bitmask is non-zero |
| `mark=<tag>` | Apply this mark to matching clients |
| `block=all` | Block all matching clients |
| `block=anonymous` | Block matching clients unless SASL authenticated |
| `class=<name>` | Assign matching clients to this connection class |
| `whitelist` | Matching clients are exempt from all blocks |
| `cachetime=<n>` | Override cache time for this DNSBL |

### Example Configuration

```
# IAuth Configuration
#IAUTH POLICY RTAWUwFr
#IAUTH CACHETIME 86400
#IAUTH DNSTIMEOUT 5
#IAUTH BLOCKMSG Sorry! Your connection has been rejected due to poor reputation.

# Block open proxies and drones (unless authenticated)
#IAUTH DNSBL server=dnsbl.dronebl.org index=2,3,5,6,7,8,9,10,13,14,15 mark=dronebl block=anonymous

# Mark Tor exit nodes but don't block
#IAUTH DNSBL server=rbl.efnetrbl.org index=4 mark=tor

# Block other bad actors
#IAUTH DNSBL server=rbl.efnetrbl.org index=1,2,3,5 mark=efnetrbl block=anonymous

# Whitelist from a private DNSBL
#IAUTH DNSBL server=whitelist.example.com whitelist cachetime=3600
```

### SASL Authentication Configuration

To enable SASL authentication handling in iauthd-ts (instead of routing to services):

1. **Create a users file** (`users` or any path you prefer):
   ```
   # Format: username:passwordhash
   # Use genhash.ts to create hashes
   admin:$5$salt$hashedpassword
   user1:$6$salt$hashedpassword
   ```

2. **Generate password hashes**:
   ```bash
   npx tsx src/genhash.ts mypassword sha256
   # Output: $5$randomsalt$hashedpasswordvalue
   ```

3. **Configure iauthd-ts**:
   ```
   #IAUTH POLICY RTAWUwFrS
   #IAUTH SASLDB /path/to/users
   #IAUTH SASLFAILMSG Invalid username or password
   ```

   The `S` in the policy enables SASL handling.

4. **Supported hash formats**:
   - `$5$salt$hash` - SHA-256 (recommended)
   - `$6$salt$hash` - SHA-512
   - `$1$salt$hash` - MD5 (legacy)
   - Plain text (for testing only)

The users file is automatically reloaded when modified (checked on each SASL attempt).

## Usage

### Command Line

```bash
node dist/index.js -c <configfile> [-v] [-d]

Options:
  -c, --config   Config file to read (required)
  -v, --verbose  Enable verbose output in iauthd
  -d, --debug    Enable debug output in IRCd
  -h, --help     Show help
```

### IRCd Configuration

Add to your `ircd.conf`:

```
IAuth {
  program = "node" "/path/to/iauthd-ts/dist/index.js" "-v" "-c" "/path/to/ircd.conf";
};
```

For Docker deployments:
```
IAuth {
  program = "node" "/home/nefarious/ircd/iauthd-ts/index.js" "-v" "-c" "/home/nefarious/ircd/ircd.conf";
};
```

### Monitoring

To see IAuth debug messages as an operator:
```
/quote mode YourNick +s 262144
```

### Statistics

IAuth statistics are available via `/stats iauth` and include:
- Uptime
- Cache size
- Total passed/rejected clients
- Per-DNSBL hit counts

## Development

### Project Structure

```
iauthd-ts/
├── src/
│   ├── index.ts      # CLI entry point
│   ├── iauth.ts      # Main IAuth daemon class
│   ├── config.ts     # Configuration parser
│   ├── dnsbl.ts      # DNSBL lookup and caching
│   ├── sasl.ts       # SASL authentication handling
│   ├── genhash.ts    # Password hash generator utility
│   └── types.ts      # TypeScript interfaces
├── users.example     # Example SASL users file
├── tests/
│   ├── config.test.ts   # Config parser tests
│   ├── dnsbl.test.ts    # DNSBL function tests
│   ├── iauth.test.ts    # Integration tests
│   └── stress.ts        # Memory stress test
├── dist/             # Compiled JavaScript (after build)
├── package.json
├── tsconfig.json
└── vitest.config.ts
```

### Building

```bash
npm install          # Install dependencies
npm run build        # Compile TypeScript to dist/
```

### Running Tests

```bash
npm test             # Run all tests
npm run test:watch   # Watch mode (re-run on changes)
npm run test:coverage # Generate coverage report
```

### Test Coverage

The test suite includes:
- **Unit tests** (45 tests): Config parsing, IP handling, DNSBL matching, caching
- **Protocol integration tests** (17 tests): IAuth protocol simulation
- **DNSBL integration tests** (32 tests): Full pipeline with mocked DNS responses

#### DNSBL Integration Tests

The DNSBL integration tests (`tests/dnsbl-integration.test.ts`) use a mock DNS resolver to test realistic scenarios:

| Category | Tests |
|----------|-------|
| Index matching | Exact match, multiple indices, no match, NXDOMAIN |
| Bitmask matching | Single bit, multiple bits, no bits match |
| block=all | Blocks both anonymous and authenticated |
| block=anonymous | Blocks anonymous, allows SASL-authenticated |
| Mark only | Accepts client but applies mark |
| Whitelist | Overrides subsequent blocking DNSBLs |
| Multiple DNSBLs | Accumulates marks, any block triggers rejection |
| Same server/different indices | AfterNET pattern (whitelist=2, rbl=250, cloud=251) |
| Class assignment | Assigns connection class from matching DNSBL |
| Real-world simulation | Full AfterNET production config scenarios |

### Stress Testing

The stress test simulates thousands of concurrent connections to verify:
- Memory stability (no leaks in client tracking)
- Cache behavior
- Performance under load

```bash
npm run stress                      # Default: 5000 clients, 120s max
npm run stress -- --clients=10000   # More clients
npm run stress -- --duration=60     # Shorter duration
npm run stress -- -v                # Verbose output
```

Example output:
```
============================================================
iauthd-ts Memory Stress Test
============================================================
Clients to simulate: 5000
Max concurrent: 100
Max duration: 120s
============================================================

Sent: 5000 | Accepted: 4994 | Rejected: 6 | Active: 0 | Cache: 5000 | Rate: 520.3/s

============================================================
STRESS TEST RESULTS
============================================================
Total clients sent:     5000
Total clients accepted: 4994
Total clients rejected: 6
Unprocessed clients:    0
Total time:             9.61s
Average rate:           520.29 clients/s

MEMORY ANALYSIS
------------------------------------------------------------
✅ Memory usage appears stable.
✅ All clients were processed correctly.
============================================================
```

### Development Mode

Run directly from TypeScript without compiling:
```bash
npm run dev -- -c /path/to/config
```

## Comparison with iauthd.pl

| Feature | iauthd.pl (Perl) | iauthd-ts (TypeScript) |
|---------|------------------|------------------------|
| Runtime | Perl + POE | Node.js |
| Async Model | POE event loop | Native async/await |
| Type Safety | None | Full TypeScript types |
| Testing | None | 62 tests + stress test |
| Dependencies | 5 CPAN modules | 0 runtime deps |

## Troubleshooting

### iauthd-ts not starting
- Check that Node.js 18+ is installed: `node --version`
- Verify config file path is correct and readable
- Check for syntax errors in `#IAUTH` directives

### Clients timing out
- Increase `DNSTIMEOUT` if DNSBL servers are slow
- Check network connectivity to DNSBL servers
- Verify DNS resolution is working: `host 2.0.0.127.dnsbl.example.com`

### High memory usage
- Reduce `CACHETIME` to expire entries sooner
- Monitor with stress test: `npm run stress`
- Check for many unique IPs (each gets cached)

### Debug output
Run with `-v` flag and set operator snomask:
```
/quote mode YourNick +s 262144
```

## License

GPL-2.0 - Same as Nefarious IRCd
