# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Nefarious IRCd** is an IRC server daemon based on ircu (the Undernet IRC daemon), extended on the `ircv3.2-upgrade` branch with a full IRCv3.2+ feature set. C codebase, GNU Autotools build, P10 server-to-server protocol. Core ircu features:
- Asynchronous event engines (epoll on Linux, kqueue on BSD, /dev/poll on Solaris)
- Dynamic configuration via F: (feature) lines
- SSL/TLS support for server-to-server and client connections

### IRCv3.2+ fork enhancements

- **Bouncer subsystem** — persistent, account-anchored sessions with a multi-connection alias model and cross-server convergence (the modern replacement for plain netsplit account-persistence). Core in `ircd/bouncer_session.c`; read the `bouncer-architecture` skill before touching `bounce_*` / BS/BX paths.
- **IRCv3 capabilities** — CAP/SASL, `draft/chathistory`, `draft/metadata-2`, `draft/multiline`, message-redaction, read-marker, event-playback, setname, echo-message, labeled-response, server-time, message-tags/msgid, batch.
- **Storage** — RocksDB backend (migrated off libmdbx) for chathistory, metadata, multiline content, and bouncer-session persistence. Built under `USE_ROCKSDB` (configure `--with-rocksdb`); the db abstraction is in `ircd/db_*.c` / `include/db_*.h`. Optional zstd compression (`--with-zstd`, `USE_ZSTD`).
- **SASL / Keycloak** — local SASL via Keycloak ROPC through libkc, three-tier AUTHENTICATE dispatch (local Keycloak / IAuth / P10 relay). `--enable-keycloak`; read the `sasl-keycloak` skill.
- **P10 extensions** — bouncer BS/BX tokens, metadata MD (MDQ retired in the era-2 overhaul), read-marker MR, TAGMSG TG, SASL relay, cache-invalidation CI. Read the `p10-protocol` skill.

## Claude Code skills & agents

Repo-local Claude knowledge lives in `.claude/` — read the relevant skill before modifying a subsystem:
- **Skills** (`.claude/skills/`): `bouncer-architecture`, `nefarious-codebase`, `sasl-keycloak`, `p10-protocol`.
- **Agents** (`.claude/agents/`): `bouncer-analyst` (read-only bouncer race/invariant analysis), `c-auditor` (codebase-wide C pattern sweeps), `p10-log-tracer` (S2S wire-log reconstruction).

A synced copy of these lives in the Afternet testnet superproject; when editing one, mirror the other.

## Build Commands

```bash
# Configure the build. RocksDB is REQUIRED — chathistory/metadata/
# bouncer storage call ml_content_*/db_* unconditionally, and history.c
# fails to compile without USE_ROCKSDB defined.
./configure --enable-debug --with-maxcon=4096 \
    --with-rocksdb=/usr --with-zstd=/usr --enable-keycloak

# Compile
make

# Install (by default to $HOME/bin, $HOME/lib)
make install

# Clean build artifacts
make clean
```

Configuration options can be viewed with `./configure --help`. Common options:
- `--enable-debug` - Enable debugging support
- `--with-maxcon=N` - Set maximum connections (default varies by platform)
- `--prefix=PATH` - Installation prefix (default: $HOME)
- `--libdir=PATH`, `--bindir=PATH`, `--mandir=PATH` - Specific install directories

## Docker Build

The multi-stage `Dockerfile` is at the repo root (GitHub Actions `docker-publish.yml` builds it on push):

```bash
docker build -t nefarious .

# The Dockerfile:
# - Debian (trixie) base; installs librocksdb-dev, libzstd-dev,
#   libcurl/libjansson (libkc), libgit2, GeoIP/MaxMindDB, cmocka
# - Runs `autoreconf -fi` to regenerate configure from configure.in
#   (the committed `configure` is treated as stale), then
#   ./configure --with-rocksdb=/usr --with-zstd=/usr --enable-keycloak ...
# - Runs as non-root user (UID/GID 1234)
```

Note: the build relies on `autoreconf -fi` producing a configure with the
RocksDB stanza. A stale `cache-from` buildx layer can reuse a configure
where `USE_ROCKSDB` was never defined, which then fails at `history.c`
(`implicit declaration of ml_content_*`). If that happens, clear the
Actions build cache and rebuild fresh.

## Configuration System

Nefarious uses a hierarchical configuration file (`ircd.conf`) with block-based syntax. The configuration format is documented in `doc/example.conf`.

### Docker Configuration

For Docker deployments, the configuration uses environment variable templating:
1. Template file: `tools/docker/base.conf-dist` contains `%VARIABLE_NAME%` placeholders
2. Entry point script: `tools/docker/dockerentrypoint.sh` substitutes environment variables via sed
3. Final config is written at container startup to `base.conf`

Required environment variables (with defaults in dockerentrypoint.sh):
- `IRCD_GENERAL_NAME` - Server name (default: localhost.localdomain)
- `IRCD_GENERAL_DESCRIPTION` - Server description
- `IRCD_GENERAL_NUMERIC` - Server numeric (0-4095, must be unique on network)
- `IRCD_ADMIN_LOCATION` - Admin location info
- `IRCD_ADMIN_CONTACT` - Admin contact info

The Docker setup uses multiple config files included by main `ircd.conf`:
- `base.conf` - Generated from base.conf-dist with variable substitution
- `local.conf` - Local server-specific settings
- `linesync.conf` - Line sync configuration

## Code Architecture

### Event Engine
Nefarious uses platform-specific event engines for efficient I/O multiplexing:
- **Linux**: `engine_epoll.c` (epoll family - most efficient)
- **FreeBSD**: `engine_kqueue.c` (kqueue)
- **Solaris**: `engine_devpoll.c` (/dev/poll)
- **Fallback**: `engine_poll.c`, `engine_select.c`

The engine is selected automatically at configure time based on platform.

### Command Handlers
IRC commands are implemented in `ircd/m_*.c` files (e.g., `m_join.c`, `m_privmsg.c`, `m_mode.c`). Each file handles one or more related IRC commands using a message table registration system.

### Core Subsystems
- **Client management**: `client.c`, `IPcheck.c` - Track connected clients and IP limits
- **Channel management**: `channel.c` - Channel state, modes, membership
- **Network I/O**: `listener.c` - Accept incoming connections; engine_*.c - Event handling
- **Protocol**: `ircd_relay.c`, `m_*.c` - P10 protocol implementation
- **Features**: `ircd_features.c` - Dynamic runtime configuration (F: lines)
- **DNS resolution**: `ircd_res.c`, `ircd_reslib.c` - Asynchronous DNS
- **Authentication**: `iauthd.pl` (external IAuth), plus local SASL via `sasl_auth.c` / `m_authenticate.c` (libkc/Keycloak)

### Fork subsystems (see `.claude/skills/`)
- **Bouncer**: `bouncer_session.c`, `m_bouncer.c` - persistent sessions, aliases, BS/BX P10 tokens
- **Chathistory / storage**: `history.c`, `chathistory_presence.c`, `ml_content.c`, `db_*.c`, `m_chathistory.c` - RocksDB-backed history + strict-presence replay
- **Metadata / read-marker**: `metadata.c`, `m_metadata.c`, `m_markread.c`
- **SASL / Keycloak**: `sasl_auth.c`, `sasl_webhook.c`, `ircd_kc_adapter.c`
- **Multiline / redaction / batch**: `m_batch.c`, `m_redact.c`

### Helper Tools
Located in `tools/`:
- `iauthd.pl` - IAuth daemon for external authentication (Perl)
- `linesync/` - Git-based configuration synchronization
- `docker/` - Docker configuration and entry point
- `convert-conf` - Convert old ircd.conf format to current format (built during make)

## Documentation

All documentation is in `doc/`:
- `example.conf` - Complete configuration file example with inline documentation
- `readme.features` - Detailed feature documentation (F: lines)
- `readme.iauth` - IAuth protocol documentation
- `p10.txt`, `p10.html` - P10 protocol specification
- `modes.txt` - Channel and user modes
- Platform-specific: `freebsd.txt`, `linux-poll.patch`
- Feature-specific: `readme.gline`, `readme.zline`, `readme.shun`, `readme.who`

## Important Notes

- Server numeric must be unique on the network and cannot be changed without restart
- Time synchronization via NTP is critical - clock skew causes serious issues
- The codebase is designed for high-performance with thousands of simultaneous connections
- SSL certificates are auto-generated by dockerentrypoint.sh if not present (ircd.pem)
