# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

iauthd-ts is a TypeScript IAuth daemon for Nefarious IRCd. It performs real-time DNS blacklist (DNSBL) lookups on connecting IRC clients and can block, mark, whitelist, or assign connection classes based on results. It also handles SASL PLAIN authentication directly (without routing to services).

This is a port of the original Perl `iauthd.pl`. The only runtime dependency is `ldapts` for LDAP authentication support.

## Build & Development Commands

```bash
npm install          # Install dependencies
npm run build        # Compile TypeScript to dist/
npm run dev -- -c /path/to/config   # Run directly from TypeScript (no compile)
npm test             # Run all tests
npm run test:watch   # Watch mode
npm run test:coverage # Coverage report
npm run stress       # Memory stress test (5000 clients)
npm run stress -- --clients=10000   # Custom client count
```

## Running

```bash
node dist/index.js -c <configfile> [-v] [-d]
# -c, --config   Config file to read (required)
# -v, --verbose  Debug output in iauthd
# -d, --debug    Debug output in IRCd
```

## Architecture

### Core Components

- **`src/index.ts`** - CLI entry point, parses args and starts daemon
- **`src/iauth.ts`** - Main `IAuthDaemon` class, handles IRCd communication via stdin/stdout using the IAuth protocol
- **`src/config.ts`** - Parses `#IAUTH` directives from config files
- **`src/dnsbl.ts`** - DNSBL lookup with caching, IP reversal utilities
- **`src/sasl.ts`** - SASL PLAIN decoding, password hashing utilities (SHA-256/512, MD5, bcrypt)
- **`src/types.ts`** - TypeScript interfaces for all data structures

### Authentication Module (`src/auth/`)

The auth module provides a modular, provider-based authentication system:

- **`src/auth/types.ts`** - AuthProvider interface and config types
- **`src/auth/manager.ts`** - AuthManager coordinates multiple providers with fallback chain
- **`src/auth/config.ts`** - Parses AUTH directive configuration
- **`src/auth/providers/file.ts`** - Static file-based authentication (wraps sasl.ts)
- **`src/auth/providers/ldap.ts`** - LDAP authentication with direct bind and search modes
- **`src/auth/providers/keycloak.ts`** - Keycloak authentication using ROPC grant

### IAuth Protocol Flow

The daemon communicates with Nefarious via stdin/stdout:

1. **Client connects** → IRCd sends `C <id> <ip> <port> <serverip> <serverport>`
2. **DNSBL lookups** → Started concurrently for all configured DNSBLs
3. **Results processed** → Check index/bitmask matches, apply marks/blocks/whitelist
4. **Hurry received** → IRCd sends `H <id> <class>` when registration timeout approaches
5. **Decision made** → Send `D` (accept), `k` (reject), or `m` (mark) back to IRCd

Key message handlers in `IAuthDaemon.handleLine()`:
- `C` - Client introduction, triggers DNSBL lookups
- `H` - Hurry, forces immediate decision
- `R` - Client authenticated via SASL/LOC (exempts from `block=anonymous`)
- `A`/`a` - SASL authentication start/continue
- `w` - Trusted WEBIRC, re-checks real IP

### DNSBL Matching

DNSBLs return `127.0.0.X` addresses where X indicates the listing reason:
- `index=2,3,4` - Match if X equals any listed value
- `bitmask=8` - Match if X AND bitmask is non-zero
- Neither specified - Any response is a match

### Caching

DNS results are cached globally in `dnsbl.ts`. Cache entries store:
- Query string (reversed IP + server)
- Result IPs or null (pending)
- Timestamp for expiration

### SASL Authentication

iauthd-ts handles SASL PLAIN authentication directly using a modular provider system:

1. IRCd sends `A <id> S :PLAIN`
2. iauthd responds with challenge `c <id> :+`
3. Client sends base64 credentials via `a <id> :<data>`
4. iauthd verifies against configured auth providers (file, LDAP, etc.)
5. Sends `L` (success) or `f` (fail) to IRCd

**Auth Provider Fallback**: When multiple providers are configured, they are tried in priority order (lower = first). First successful authentication wins.

Password formats for file provider: `$5$salt$hash` (SHA-256), `$6$salt$hash` (SHA-512), `$1$salt$hash` (MD5), `$2a$` or `$2b$` (bcrypt)

## Testing

Tests use Vitest with mocked DNS resolution:

- **`tests/config.test.ts`** - Configuration parsing
- **`tests/dnsbl.test.ts`** - IP functions, caching, matching
- **`tests/dnsbl-integration.test.ts`** - Full DNSBL pipeline with mock DNS
- **`tests/iauth.test.ts`** - Protocol integration tests
- **`tests/sasl.test.ts`** - SASL authentication utilities
- **`tests/auth/config.test.ts`** - AUTH directive parsing
- **`tests/auth/file.test.ts`** - FileAuthProvider tests
- **`tests/auth/manager.test.ts`** - AuthManager fallback behavior
- **`tests/auth/keycloak.test.ts`** - KeycloakAuthProvider tests
- **`tests/stress.ts`** - Memory stress test (not a vitest file)

Run a single test file:
```bash
npx vitest run tests/dnsbl.test.ts
npx vitest run tests/config.test.ts -t "parses DNSBL"  # Run matching tests
```

## Configuration

Configuration uses `#IAUTH` directives embedded in ircd.conf (IRCd ignores lines starting with `#`):

```
#IAUTH POLICY RTAWUwFrS
#IAUTH DNSTIMEOUT 5
#IAUTH CACHETIME 86400
#IAUTH BLOCKMSG Your connection has been rejected
#IAUTH DNSBL server=dnsbl.dronebl.org index=2,3,5 mark=dronebl block=anonymous
#IAUTH DNSBL server=whitelist.example.com whitelist
```

### Authentication Providers

Use `#IAUTH AUTH` to configure authentication backends. Multiple providers can be configured; they are tried in priority order (lower = first).

#### Static File Provider
```
#IAUTH SASLDB /path/to/users                          # Legacy format (still supported)
#IAUTH AUTH provider=file path=/path/to/users         # Explicit format
#IAUTH AUTH provider=file path=/path/to/users priority=50
```

#### LDAP Direct Bind Mode
User binds directly with their credentials using a DN template:
```
#IAUTH AUTH provider=ldap uri=ldap://ldap.example.com:389 mode=direct userdn=uid=%s,ou=users,dc=example,dc=com
```

#### LDAP Search Mode (Admin Bind + Search)
Binds as admin, searches for user, optionally checks group membership, then binds as user:
```
#IAUTH AUTH provider=ldap uri=ldaps://ldap.example.com:636 mode=search basedn=ou=users,dc=example,dc=com binddn=cn=admin,dc=example,dc=com bindpass=secret userfilter=(uid=%s)

# With group membership check:
#IAUTH AUTH provider=ldap uri=ldaps://ldap.example.com:636 mode=search basedn=ou=users,dc=example,dc=com binddn=cn=admin,dc=example,dc=com bindpass=secret userfilter=(uid=%s) groupdn=cn=ircusers,ou=groups,dc=example,dc=com
```

#### LDAP Configuration Options

| Option | Required | Mode | Description |
|--------|----------|------|-------------|
| `uri` | Yes | Both | LDAP server URI (`ldap://` or `ldaps://`) |
| `mode` | Yes | Both | `direct` or `search` |
| `userdn` | Yes | direct | DN template with `%s` for username |
| `basedn` | Yes | search | Base DN for user search |
| `binddn` | Yes | search | Admin bind DN |
| `bindpass` | Yes | search | Admin bind password |
| `userfilter` | Yes | search | Search filter with `%s` for username |
| `groupdn` | No | search | Group DN for membership check |
| `accountattr` | No | Both | Attribute to use as account name (default: uid/sAMAccountName) |
| `timeout` | No | Both | Connection timeout in ms (default: 5000) |
| `priority` | No | Both | Provider priority (default: 100, lower = first) |

#### Keycloak Provider
Uses Resource Owner Password Credentials (ROPC) grant to authenticate users against Keycloak. The client must have "Direct Access Grants" enabled in Keycloak.

```
#IAUTH AUTH provider=keycloak url=https://keycloak.example.com realm=myrealm clientid=irc-client

# With client secret (for confidential clients):
#IAUTH AUTH provider=keycloak url=https://keycloak.example.com realm=myrealm clientid=irc-client clientsecret=your-secret

# With custom account attribute:
#IAUTH AUTH provider=keycloak url=https://keycloak.example.com realm=myrealm clientid=irc-client accountattr=irc_nick
```

#### Keycloak Configuration Options

| Option | Required | Description |
|--------|----------|-------------|
| `url` | Yes | Keycloak server URL (e.g., `https://keycloak.example.com`) |
| `realm` | Yes | Keycloak realm name |
| `clientid` | Yes | OAuth2 client ID (must have Direct Access Grants enabled) |
| `clientsecret` | No | Client secret (for confidential clients) |
| `accountattr` | No | JWT claim to use as account name (default: `preferred_username`) |
| `timeout` | No | Request timeout in ms (default: 5000) |
| `priority` | No | Provider priority (default: 100, lower = first) |

#### Keycloak Server Setup

To configure Keycloak for IRC SASL authentication:

**1. Create a Realm**
- Go to Keycloak Admin Console
- Create a new realm (e.g., `irc` or `testnet`)

**2. Create a Client**
- Go to **Clients** → **Create client**
- **Client ID**: `irc-client` (or your preferred name)
- **Client Protocol**: `OpenID Connect` (not SAML)
- Click **Next**
- **Client authentication**: `OFF` (for public client) or `ON` if using `clientsecret`
- **Direct access grants**: `ON` ← **Critical for ROPC authentication**
- Click **Save**

**3. Configure User Profile (Optional but Recommended)**
- Go to **Realm Settings** → **User profile**
- Click on `firstName` → set "Required field" to `OFF` → Save
- Click on `lastName` → set "Required field" to `OFF` → Save
- This prevents "Account is not fully set up" errors for users without names

**4. Configure Authentication Flows (Optional)**
- Go to **Authentication** → **Flows** → select **direct grant**
- Ensure no required actions block password auth (e.g., set Conditional OTP to `DISABLED` if not using 2FA)

**5. Create Users**
- Go to **Users** → **Add user**
- Set username, email (if required)
- Go to **Credentials** tab → **Set password**
- **Important**: Set **Temporary** to `OFF` to avoid forced password change
- Ensure **Required user actions** is empty (no "Update Password", "Configure OTP", etc.)

**Common Issues**
- `"Account is not fully set up"` - User has pending required actions (check user's Required Actions field, or realm-level User Profile requirements)
- `"Wrong client protocol"` - Client is configured as SAML instead of OpenID Connect
- `"unauthorized_client"` - Direct Access Grants is not enabled on the client
- Connection errors - Use `http://` for dev mode (`start-dev`), `https://` for production

**Testing Authentication**
```bash
curl -s -X POST "http://localhost:8080/realms/REALM/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=CLIENT_ID&username=USER&password=PASS"
```

A successful response returns an `access_token`. Error responses include `error` and `error_description` fields.

### Password Hashes

Generate password hashes for the file provider:
```bash
npx tsx src/genhash.ts mypassword sha256
```
