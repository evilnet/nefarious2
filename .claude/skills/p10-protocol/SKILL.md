---
name: p10-protocol
description: P10 server-to-server protocol reference for Nefarious and X3 — message and numeric format, command tokens, IP encoding, the SASL flow, and IRCv3 S2S extensions (MD/MDQ metadata, MR read markers, TG tagmsg). Use when parsing or emitting P10, debugging BURST/SQUIT, or adding S2S commands.
---

# P10 Protocol Skill

This skill provides expertise on the P10 server-to-server protocol used between Nefarious IRCd and X3 Services.

## Protocol Overview

P10 is the server-to-server protocol used by Undernet-derived IRC servers (including Nefarious). Messages use numeric identifiers for servers and users rather than names.

## Message Format

```
[SOURCE_NUMERIC] [TOKEN] [PARAMETERS...]
```

- **Source Numeric**: 2-char server numeric or 5-char user numeric (server + 3-char client)
- **Token**: 1-2 character command abbreviation (defined in `msg.h`)
- **Parameters**: Space-separated, last param can be prefixed with `:` for spaces

## Numeric Format

| Type | Format | Example | Description |
|------|--------|---------|-------------|
| Server | 2 chars | `AB` | Base64-encoded server ID |
| User | 5 chars | `ABAAA` | Server (2) + client suffix (3) |

The numeric is derived from the server's position in the network and uses a base64-like encoding (A-Z, a-z, 0-9, [, ]).

## Complete P10 Token Reference

### Core Commands
| Token | Full Command | Purpose |
|-------|--------------|---------|
| `N` | NICK | Introduce user / nick change |
| `Q` | QUIT | User disconnect |
| `S` | SERVER | Server introduction |
| `SQ` | SQUIT | Server quit |
| `P` | PRIVMSG | Private message |
| `O` | NOTICE | Notice message |
| `G` | PING | Ping request |
| `Z` | PONG | Ping response |

### Channel Commands
| Token | Full Command | Purpose |
|-------|--------------|---------|
| `J` | JOIN | Channel join |
| `L` | PART | Channel part |
| `K` | KICK | Channel kick |
| `I` | INVITE | Channel invite |
| `M` | MODE | Mode change |
| `T` | TOPIC | Topic change |
| `C` | CREATE | Channel creation |
| `B` | BURST | Netburst channel state |

### Services Commands
| Token | Full Command | Purpose |
|-------|--------------|---------|
| `AC` | ACCOUNT | Set/update user account |
| `FA` | FAKE/FAKEHOST | Set virtual host |
| `SASL` | SASL | SASL authentication relay |
| `MK` | MARK | Mark user with metadata |
| `SW` | SWHOIS | Set WHOIS extra info |
| `SM` | SVSMODE | Services mode change |
| `SN` | SVSNICK | Force nick change |
| `SJ` | SVSJOIN | Force channel join |
| `SP` | SVSPART | Force channel part |
| `SX` | SVSQUIT | Force quit |
| `SE` | SETNAME | Change user realname (GECOS) |

### Administrative
| Token | Full Command | Purpose |
|-------|--------------|---------|
| `D` | KILL | Kill user |
| `GL` | GLINE | G-line (global ban) |
| `SU` | SHUN | Shun user |
| `ZL` | ZLINE | Z-line (IP ban) |
| `OM` | OPMODE | Oper mode change |
| `CM` | CLEARMODE | Clear channel modes |

### Netburst
| Token | Full Command | Purpose |
|-------|--------------|---------|
| `EB` | END_OF_BURST | End of netburst |
| `EA` | EOB_ACK | End of burst acknowledgment |

## SASL P10 Protocol

### Message Format
```
SASL <target> <source>!<fd>.<cookie> <subcmd> <data> [ext]
```

- **target**: Server numeric to route to (or `*` for broadcast)
- **source**: Server numeric that originated the request
- **fd**: File descriptor of the client connection
- **cookie**: Random session identifier for correlation
- **subcmd**: Single-character operation code
- **data**: Base64-encoded payload or mechanism name
- **ext**: Optional extension data (e.g., SSL client fingerprint)

### SASL Subcmd Codes

| Code | Direction | Meaning | Nef Handler | X3 Handler |
|------|-----------|---------|-------------|------------|
| `S` | Nef→X3 | Start (mechanism name) | Outbound only | `handle_sasl_input()` |
| `H` | Nef→X3 | Host info (`user@host:ip`) | Outbound only | `handle_sasl_input()` |
| `C` | Both | Continue (base64 auth data) | `m_sasl.c:178` | `handle_sasl_input()` |
| `D` | Both | Done (`S`=success, `F`=fail, `A`=abort) | `m_sasl.c:197` | `handle_sasl_input()` |
| `L` | X3→Nef | Login (account name, timestamp) | `m_sasl.c:181` | Outbound only |
| `M` | X3→Nef | Mechanisms list (for 908 numeric) | `m_sasl.c:212` | Outbound only |

**Important**: X3 may send `I` (Impersonation) but Nefarious does NOT handle it - silently ignored.

### SASL Flow - Pre-Registration

```
Client              Nefarious                    X3
  |                     |                         |
  |--CAP REQ :sasl----->|                         |
  |<--CAP ACK :sasl-----|                         |
  |--AUTHENTICATE PLAIN-|                         |
  |                     |--SASL tgt src S PLAIN-->|
  |                     |--SASL tgt src H user@host:ip
  |                     |                         |
  |                     |<--SASL src tgt C +------|  (request creds)
  |<--AUTHENTICATE +----|                         |
  |                     |                         |
  |--AUTHENTICATE <b64>-|                         |
  |                     |--SASL tgt src C <b64>-->|
  |                     |                         |
  |                     |<--SASL src tgt L acct---|  (login info)
  |                     |<--SASL src tgt D S------|  (done, success)
  |<--904 LOGGEDIN------|                         |
  |<--903 SASLSUCCESS---|                         |
  |--CAP END----------->|                         |
  |                     |                         |
```

### SASL Flow - Post-Registration (REAUTHENTICATE)

For token refresh after the user is already registered (introduced via `N`):

```
Client              Nefarious                    X3
  |                     |                         |
  |--AUTHENTICATE OAUTH-|                         |
  |                     |--SASL tgt src S OAUTH-->|  (reuse S subcmd)
  |                     |--SASL tgt src H user@host:ip
  |                     |                         |
  |                     |<--SASL src tgt C +------|
  |<--AUTHENTICATE +----|                         |
  |                     |                         |
  |--AUTHENTICATE <jwt>-|                         |
  |                     |--SASL tgt src C <jwt>-->|
  |                     |                         |
  |                     |<--SASL src tgt L newacct|  (may be same or different)
  |                     |<--SASL src tgt D S------|
  |<--904 LOGGEDIN------|                         |
  |<--903 SASLSUCCESS---|                         |
  |                     |                         |
  |                     |==AC usrnum newacct ts==>|  (broadcast if registered)
```

**Key**: After successful post-registration SASL, Nefarious MUST send `AC` to propagate the account change network-wide (only if user was already introduced via `N`).

## ACCOUNT (AC) Command

The AC command has two formats depending on the `FEAT_EXTENDED_ACCOUNTS` setting.

### Non-Extended Format (FEAT_EXTENDED_ACCOUNTS = FALSE)
```
[SERVER] AC [USER_NUMERIC] [ACCOUNT_NAME] [TIMESTAMP]
```

Example:
```
AB AC ABAAB accountname 1703345678
```

### Extended Format (FEAT_EXTENDED_ACCOUNTS = TRUE)
```
[SERVER] AC [USER_NUMERIC] [SUBTYPE] [ACCOUNT_NAME] [TIMESTAMP]
```

#### Subtypes
| Code | Meaning |
|------|---------|
| `R` | Register (new account login) |
| `U` | Unregister (logout) |
| `M` | Modify (account change) |

Example:
```
AB AC ABAAB R accountname 1703345678
```

### When to Send AC
- After successful SASL for a **registered** user (already introduced via `N`)
- When user logs in via NickServ IDENTIFY
- When user's account changes for any reason

**Important**: Always check `feature_bool(FEAT_EXTENDED_ACCOUNTS)` to determine which format to use.

## FAKEHOST (FA) Command

### Format
```
[SERVER] FA [USER_NUMERIC] [HOSTNAME]
```

Used for virtual hosts/cloaking. Fully implemented in both Nefarious (`TOK_FAKE`) and X3 (`irc_fakehost()`).

### Example
```
AB FA ABAAB user.vhost.network
```

## Key Implementation Files

### Nefarious
| File | Purpose |
|------|---------|
| `include/msg.h` | Token definitions (`MSG_*`, `TOK_*`, `CMD_*`) |
| `ircd/parse.c` | P10 message parsing and routing |
| `ircd/m_sasl.c` | SASL P10 message handler (inbound from X3) |
| `ircd/m_authenticate.c` | Client AUTHENTICATE → SASL P10 outbound |
| `ircd/send.c` | `sendcmdto_*` functions for P10 output |

### X3
| File | Purpose |
|------|---------|
| `src/proto-p10.c` | P10 protocol implementation, all `irc_*()` functions |
| `src/nickserv.c` | SASL handling (`sasl_packet()`, `handle_sasl_input()`) |
| `src/nickserv.c:6416` | `struct SASLSession` definition |

## X3 SASL Session Structure

```c
struct SASLSession {
    struct SASLSession* next;
    struct SASLSession* prev;
    struct server* source;      // Originating server
    char* buf, *p;              // Message buffer
    int buflen;
    char uid[128];              // Client identifier (server!fd.cookie)
    char mech[16];              // Mechanism (PLAIN, EXTERNAL, OAUTHBEARER)
    char* sslclifp;             // SSL client fingerprint
    char* hostmask;             // user@host:ip from H subcmd
    int flags;                  // SDFLAG_STALE etc.
};
```

## SETNAME (SE) P10 Command

The SETNAME command allows users to change their realname (GECOS field) mid-session.

### P10 Message Format
```
[USER_NUMERIC] SE :[NEW_REALNAME]
```

### Example
```
ABAAB SE :This is my new realname
```

### Direction
- **Client→Server**: User sends `SETNAME :newname` command
- **Server→Server**: Propagated via P10 `SE` token
- **Server→Client**: Sent to channel members with `setname` capability

### Client Protocol (IRCv3)
```
Client: SETNAME :New Real Name
Server: :nick!user@host SETNAME :New Real Name
```

The client-facing SETNAME is only sent to users who have negotiated the `setname` capability.

### Implementation Notes
1. Realname is truncated to REALLEN (50 characters) if too long
2. Message is only propagated if realname actually changed
3. Local clients receive notification via `sendcmdto_common_channels_capab_butone()`
4. Feature flag: `FEAT_CAP_setname` (default: TRUE)

### Services (X3) Handling
X3 does not currently need to handle SETNAME for channel services purposes, but should parse and ignore unknown commands gracefully. The realname change is informational only.

---

## Validation Rules for P10 Changes

When reviewing P10 protocol changes:

1. **Backward Compatibility**: New subcmds should be additive; old servers should ignore unknown codes
2. **Numeric Format**: Server numerics are 2 chars, user numerics are 5 chars (server + 3-char suffix)
3. **Token Consistency**: Use existing tokens where applicable before creating new ones
4. **Direction Matters**: Verify which direction (Nef→X3 or X3→Nef) the message flows
5. **Handler Existence**: Check if Nefarious actually handles the subcmd (see table above)
6. **Cookie Preservation**: SASL sessions use `fd.cookie` for correlation - must be preserved across the session
7. **Account Propagation**: After successful auth for registered users, `AC` must be sent network-wide
8. **Token Definitions**: New commands need entries in `msg.h` (`MSG_*`, `TOK_*`, `CMD_*`)

## Common Mistakes to Avoid

1. **Assuming all X3 subcmds are handled by Nefarious** - e.g., `I` (Impersonation) is ignored
2. **Creating new P10 commands when existing ones suffice** - e.g., reuse `S` for reauth instead of new subcmd
3. **Forgetting to send `AC` after successful post-registration SASL**
4. **Incorrect numeric format** - must match server/user context
5. **Missing the `H` (host info) message after `S` in SASL flow**
6. **Not checking `IsSASLComplete()` state correctly** - this blocks re-auth in current code
7. **Forgetting that SASL data >400 bytes is chunked** - multiple `C` messages are concatenated

## Testing P10 Changes

1. **Packet Capture**: Use `tcpdump` or similar to capture S2S traffic
2. **Debug Logging**: Both Nefarious and X3 have debug log levels for SASL
3. **Single Server Test**: Test with one Nefarious + one X3 first
4. **Multi-Server Test**: Verify `AC` propagation across multiple servers
5. **Error Cases**: Test auth failure, timeout, abort scenarios

---

## Feature Flags Affecting P10 Protocol

Many Nefarious feature flags change P10 message formats or behavior. When writing P10-related code, always check for these feature flags.

### FEAT_EXTENDED_ACCOUNTS

**Default**: TRUE

Affects the ACCOUNT (AC) command format.

| Setting | Format | Example |
|---------|--------|---------|
| FALSE | `AC <user> <account> [timestamp]` | `AB AC ABAAB myaccount 1703345678` |
| TRUE | `AC <user> <subtype> <account> [timestamp]` | `AB AC ABAAB R myaccount 1703345678` |

**Subtypes for extended format**:
- `R` - Register (first login)
- `M` - Modify (account change)
- `U` - Unregister (logout)
- `C` - LOC request
- `H` - LOC request with host info
- `S` - LOC request with host + SSL fingerprint
- `A` - LOC accepted
- `D` - LOC denied

**Code pattern**:
```c
if (feature_bool(FEAT_EXTENDED_ACCOUNTS)) {
    sendcmdto_serv_butone(&me, CMD_ACCOUNT, NULL, "%C %c %s %Tu",
                          acptr, type, account, timestamp);
} else {
    sendcmdto_serv_butone(&me, CMD_ACCOUNT, NULL, "%C %s %Tu",
                          acptr, account, timestamp);
}
```

### FEAT_SASL_SENDHOST

**Default**: TRUE

When enabled, Nefarious sends the `H` (host info) subcmd after `S` in SASL flow.

```
SASL target source!fd.cookie H :user@host:ip
```

**Code pattern**:
```c
if (feature_bool(FEAT_SASL_SENDHOST))
    sendcmdto_one(&me, CMD_SASL, acptr, "%C %C!%u.%u H :%s@%s:%s",
                  acptr, &me, cli_fd(cptr), cli_saslcookie(cptr),
                  cli_username(cptr), realhost, cli_sock_ip(cptr));
```

### FEAT_LOC_SENDHOST / FEAT_LOC_SENDSSLFP

**Defaults**: FALSE / FALSE

Controls Login-On-Connect (LOC) message format.

| LOC_SENDHOST | LOC_SENDSSLFP | AC Subcmd | Format |
|--------------|---------------|-----------|--------|
| FALSE | - | `C` | `AC target C .fd.cookie account :password` |
| TRUE | FALSE | `H` | `AC target H .fd.cookie user@host:ip account :password` |
| TRUE | TRUE | `S` | `AC target S .fd.cookie user@host:ip sslfingerprint account :password` |

### FEAT_OPLEVELS

**Default**: FALSE

Enables channel operator levels (+A/+U passwords, numeric op levels).

Affects BURST message user list format:
```
# Without oplevels:
B #chan 1234567890 +nt ABAAB,ABAAC:o,ABAAD:v

# With oplevels (op level number after mode chars):
B #chan 1234567890 +nt ABAAB,ABAAC:o999,ABAAD:v
```

**Server flag**: Servers with oplevels support include `o` in their SERVER flags.

### FEAT_HALFOPS

**Default**: FALSE

Enables half-operator mode (+h).

Affects:
- MODE messages: `+h` / `-h` user modes
- BURST user list: `:h` membership mode

```
# BURST with halfops:
B #chan 1234567890 +nt ABAAB:h,ABAAC:o,ABAAD:oh
```

**Note**: Server accepts halfops from other servers even if disabled locally (prevents desync).

### FEAT_EXCEPTS

**Default**: FALSE

Enables ban exceptions (+e mode).

Affects BURST message format - exception list follows bans, prefixed with `~`:
```
# BURST with exceptions:
B #chan 1234567890 +nt ABAAB :%*!*@banned.host ~ *!*@excepted.host
```

**Warning**: Breaks services that don't parse the extended BURST format.

### FEAT_EXTBANS

**Default**: FALSE

Enables extended ban syntax (e.g., `~a:account`, `~c:#channel`).

Only controls client ability to set extended bans; server still accepts them from network.

### FEAT_HOST_HIDING_STYLE

**Default**: 1

Affects hidden host format in NICK messages and FAKEHOST.

| Value | Format | Example |
|-------|--------|---------|
| 1 | `account.network.tld` | `myaccount.users.afternet.org` |
| 2 | `Prefix-HASH.host.tld` | `Nefarious-554F4C88D.isp.com` |
| 3 | Hybrid (both styles) | Either format |

Affects umode `+x` behavior and `FA` (FAKEHOST) command generation.

### FEAT_SASL_AUTOHIDEHOST

**Default**: TRUE

Automatically sets `+x` (hidden host) on successful SASL authentication.

Requires `HOST_HIDING_STYLE` = 1 or 3.

```c
if (((feature_int(FEAT_HOST_HIDING_STYLE) == 1) ||
     (feature_int(FEAT_HOST_HIDING_STYLE) == 3)) &&
    feature_bool(FEAT_SASL_AUTOHIDEHOST)) {
  SetHiddenHost(acptr);
}
```

### FEAT_SASL_SERVER

**Default**: "*"

Specifies SASL provider server.

| Value | Behavior |
|-------|----------|
| `*` | Broadcast SASL to all servers, first responder wins |
| `services.*` | Send directly to matching server |

### FEAT_SASL_TIMEOUT

**Default**: 8 (seconds)

SASL authentication timeout. After expiry, sends `D A` (abort) to services.

### FEAT_LOC_TIMEOUT

**Default**: 3 (seconds)

Login-On-Connect timeout.

---

## NICK Message Mode Parameters

The NICK (N) message for user introduction includes optional mode parameters. These modes have parameters that MUST appear in a specific order for backward compatibility:

```
N <nick> <hops> <TS> <user> <host> [+modes [mode_params...]] <IP> <numeric> :<realname>
```

### Mode Parameter Order (CRITICAL)

When modes have parameters, they must appear in this exact sequence:

1. `+r` - Account name (if logged in)
2. `+h` - Virtual user@host (sethost)
3. `+f` - Fake host
4. `+C` - Cloaked host
5. `+c` - Cloaked IP

**Example**:
```
AB N TestUser 1 1703345678 user host.com +rxf accountname user@vhost.net AAAAAB ABAAB :Real Name
```

**Warning**: Many services break parsing if this order isn't followed, especially when `+h` is present but they don't support it.

---

## Multiline Batch Protocol (ML)

The ML (MULTILINE) command enables S2S relay of multiline batched messages from clients using the IRCv3 `draft/multiline` capability.

### P10 Message Format

```
[USER_NUMERIC] ML +batchid target :first_line     # Start batch with first line
[USER_NUMERIC] ML batchid target :line            # Normal continuation
[USER_NUMERIC] ML cbatchid target :line           # Concat continuation
[USER_NUMERIC] ML -batchid target :               # End batch
```

### Parameters
- **batchid**: Unique identifier for the batch (typically `servernum+timestamp`)
- **target**: Channel name or user nick
- **prefix**: `+` (start), none or `c` (continuation), `-` (end)

### Example S2S Flow

```
ABAAB ML +Bj1703345678 #channel :Line one
ABAAB ML Bj1703345678 #channel :Line two
ABAAB ML cBj1703345678 #channel :continued...
ABAAB ML -Bj1703345678 #channel :
```

### Token Definition

```c
// In msg.h
#define MSG_MULTILINE   "MULTILINE"
#define TOK_MULTILINE   "ML"
#define CMD_MULTILINE   MSG_MULTILINE, TOK_MULTILINE
```

### Client-Facing Multiline Messages

When delivering multiline batches to clients with the `message-tags` capability, messages MUST include `msgid` and `time` tags:

```
@batch=<batchid>;time=<iso8601>;msgid=<msgid> :sender!user@host PRIVMSG target :text
```

**Important**: The `msgid` tag is required by the IRCv3 message-ids specification for all PRIVMSGs and NOTICEs sent to clients that have negotiated `message-tags`. This includes messages inside batches.

### Client Capability Requirements

For proper multiline batch delivery:

| Client Caps | Delivery Format |
|-------------|-----------------|
| `draft/multiline` + `batch` | BATCH with individual PRIVMSGs |
| `draft/multiline` + `batch` + `message-tags` | BATCH with PRIVMSGs including `msgid`/`time` |
| Neither | Fallback to individual PRIVMSGs |

### Implementation Notes

1. **msgid generation**: Each message in the batch gets a unique msgid, generated via `generate_msgid()` in `send.c`
2. **time tag**: ISO 8601 timestamp with millisecond precision (e.g., `2025-12-30T12:58:45.101Z`)
3. **concat flag**: Messages with `draft/multiline-concat` tag should be concatenated with the previous line by the receiver
4. **S2S relay**: The `ML` P10 command propagates multiline batches between servers; receiving servers regenerate client-facing batches with fresh msgids

### Files

| File | Purpose |
|------|---------|
| `ircd/m_batch.c` | Client BATCH handler, multiline processing, S2S relay |
| `ircd/send.c` | `generate_msgid()` and tag formatting functions |
| `include/send.h` | Public API including `generate_msgid()` declaration |

---

## IRCv3 Message Tags in Batched Messages

All IRC messages sent to clients supporting `message-tags` capability MUST include server-generated tags according to the IRCv3 specifications.

### Required Tags for PRIVMSG/NOTICE

| Tag | Required When | Format | Example |
|-----|---------------|--------|---------|
| `msgid` | Client has `message-tags` | `msgid=<unique-id>` | `msgid=Bj-1703345678-42` |
| `time` | Client has `server-time` | `time=<ISO8601>` | `time=2025-12-30T12:58:45.101Z` |
| `batch` | Inside a batch | `batch=<batchid>` | `batch=Bj127598488` |

### msgid Format

The server generates msgids in the format:
```
<server_numeric>-<startup_ts>-<counter>
```

Example: `Bj-1703345678-42`

### Implementation in m_batch.c

When sending batched messages, the code checks for `CAP_MSGTAGS`:

```c
int use_tags = CapActive(to, CAP_MSGTAGS);

if (use_tags) {
    format_time_tag(timebuf, sizeof(timebuf));
    generate_msgid(msgidbuf, sizeof(msgidbuf));
    sendrawto_one(to, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                  batchid, timebuf, msgidbuf, ...);
} else {
    sendrawto_one(to, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                  batchid, ...);
}
```

### Code Paths Requiring msgid

All these code paths MUST include msgid/time when the recipient supports message-tags:

1. **Channel delivery** (`process_multiline_batch`)
   - Sending to channel members with multiline+batch

2. **Echo-message** (`process_multiline_batch`)
   - Echo back to sender with echo-message enabled

3. **Private messages** (`process_multiline_batch`)
   - Direct messages to users with multiline+batch

4. **S2S relay delivery** (`deliver_s2s_multiline_batch`)
   - When receiving ML from another server and delivering to local clients
