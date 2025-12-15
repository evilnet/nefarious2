# Linesync Sidecar Container

A Docker sidecar container for automated git-based configuration synchronization with Nefarious IRCd. This container periodically pulls configuration updates from a git repository and signals the IRCd to reload.

## Features

- Git-based configuration sync using SSH authentication
- Automatic SIGHUP signaling to nefarious container when config changes
- Configurable sync interval
- Support for SSL certificate sync via git tags
- Multiple operation modes: keygen, setup, sync, once
- Automatic UID/GID remapping via fixuid for bind mount compatibility

## Quick Start

### 1. Build the container

```bash
cd tools/linesync
docker build -t linesync .
```

### 2. Create directories and generate SSH keys

```bash
mkdir -p ./linesync-ssh ./linesync
docker run --rm -u "$(id -u):$(id -g)" \
  -v ./linesync-ssh:/home/linesync/.ssh \
  linesync keygen
```

This outputs a public key. Add it to your git repository's deploy keys.

### 3. Initial repository setup

```bash
docker run --rm -u "$(id -u):$(id -g)" \
  -v ./linesync-ssh:/home/linesync/.ssh \
  -v ./local.conf:/home/linesync/ircd/local.conf \
  -v ./linesync:/home/linesync/ircd/linesync \
  -e GIT_REPOSITORY=git@github.com:yourorg/linesync-data.git \
  linesync setup
```

### 4. Run continuous sync

```bash
docker run -d \
  --name linesync \
  -u "$(id -u):$(id -g)" \
  -v ./linesync-ssh:/home/linesync/.ssh \
  -v ./local.conf:/home/linesync/ircd/local.conf \
  -v ./linesync:/home/linesync/ircd/linesync \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e NEFARIOUS_CONTAINER=nefarious \
  -e SYNC_INTERVAL=300 \
  -e IRCD_CONF=/home/linesync/ircd/local.conf \
  linesync sync
```

## Command Line Usage

**Note:** Use `-u "$(id -u):$(id -g)"` to match your host user's UID/GID for proper file permissions on bind mounts.

### Generate SSH keypair

```bash
mkdir -p ./linesync-ssh

# Generate ed25519 key (default, recommended)
docker run --rm -u "$(id -u):$(id -g)" \
  -v ./linesync-ssh:/home/linesync/.ssh \
  linesync keygen

# Generate RSA key
docker run --rm -u "$(id -u):$(id -g)" \
  -v ./linesync-ssh:/home/linesync/.ssh \
  linesync keygen rsa
```

### Initial setup (clone repository)

```bash
mkdir -p ./linesync
docker run --rm -u "$(id -u):$(id -g)" \
  -v ./linesync-ssh:/home/linesync/.ssh \
  -v ./local.conf:/home/linesync/ircd/local.conf \
  -v ./linesync:/home/linesync/ircd/linesync \
  -e GIT_REPOSITORY=git@github.com:yourorg/linesync-data.git \
  linesync setup
```

### Run sync once

```bash
docker run --rm -u "$(id -u):$(id -g)" \
  -v ./linesync-ssh:/home/linesync/.ssh \
  -v ./local.conf:/home/linesync/ircd/local.conf \
  -v ./linesync:/home/linesync/ircd/linesync \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e IRCD_CONF=/home/linesync/ircd/local.conf \
  linesync once
```

### Interactive shell (debugging)

```bash
docker run --rm -it -u "$(id -u):$(id -g)" \
  -v ./linesync-ssh:/home/linesync/.ssh \
  -v ./local.conf:/home/linesync/ircd/local.conf \
  -v ./linesync:/home/linesync/ircd/linesync \
  linesync shell
```

## Docker Compose Example

```yaml
services:
  nefarious:
    image: ghcr.io/evilnet/nefarious2:latest
    container_name: nefarious
    volumes:
      - ./ircd.pem:/home/nefarious/ircd/ircd.pem
      - ./local.conf:/home/nefarious/ircd/local.conf
    ports:
      - "6667:6667"
      - "4497:4497"

  linesync:
    image: ghcr.io/evilnet/nefarious2-linesync:latest
    container_name: linesync
    # Match your host user's UID:GID for bind mount permissions
    user: "${UID}:${GID}"
    depends_on:
      - nefarious
    volumes:
      # SSH keys directory
      - ./linesync-ssh:/home/linesync/.ssh
      # Config file - same bind mount as nefarious
      - ./local.conf:/home/linesync/ircd/local.conf
      # Linesync git repo directory
      - ./linesync:/home/linesync/ircd/linesync
      # Docker socket for signaling
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      NEFARIOUS_CONTAINER: nefarious
      SYNC_INTERVAL: 300
      IRCD_CONF: /home/linesync/ircd/local.conf
      # Optional: sync SSL certs from git tag
      # CERT_TAG: myserver-cert
```

### Initial Setup with Compose

```bash
# 0. Create required directories
mkdir -p ./linesync-ssh ./linesync
touch ./local.conf

# 1. Generate SSH key
UID=$(id -u) GID=$(id -g) docker compose run --rm linesync keygen

# 2. Add the public key to your git repo's deploy keys

# 3. Clone the linesync repository
UID=$(id -u) GID=$(id -g) docker compose run --rm \
  -e GIT_REPOSITORY=git@github.com:yourorg/linesync-data.git \
  linesync setup

# 4. Start the services
UID=$(id -u) GID=$(id -g) docker compose up -d
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SYNC_INTERVAL` | `300` | Seconds between sync attempts |
| `IRCD_CONF` | `/home/linesync/ircd/ircd.conf` | Path to ircd.conf |
| `IRCD_PID` | `/home/linesync/ircd/ircd.pid` | Path to ircd.pid (not used for Docker signaling) |
| `SSH_KEY` | `/home/linesync/.ssh/id_ed25519` | Path to SSH private key |
| `NEFARIOUS_CONTAINER` | `nefarious` | Container name to send SIGHUP |
| `GIT_REPOSITORY` | (none) | Git repository URL (required for setup) |
| `CERT_TAG` | (none) | Git tag containing SSL certificate |

## Volume Mounts

| Path | Purpose |
|------|---------|
| `/home/linesync/.ssh` | SSH keys directory (persistent) |
| `/home/linesync/ircd` | IRCd config directory (shared with nefarious) |
| `/var/run/docker.sock` | Docker socket for container signaling |

## How It Works

1. The sidecar runs `gitsync.sh` at regular intervals
2. `gitsync.sh` pulls updates from the configured git repository
3. If the config changed, the sidecar sends SIGHUP to the nefarious container via the Docker API
4. Nefarious reloads its configuration without restarting

### Config File Structure

Your git repository should contain a `linesync.data` file with IRC configuration blocks. These are merged into your `ircd.conf` between special marker comments:

```
# BEGIN LINESYNC
... (managed by linesync) ...
# END LINESYNC
```

The markers are added automatically on first sync if not present.

## SSL Certificate Sync

You can also sync SSL certificates stored as git tags:

```bash
# Store a certificate in git (run this on your cert management system)
git tag -f myserver-cert $(cat fullchain.pem | git hash-object -w --stdin)
git push origin :refs/tags/myserver-cert  # Delete old tag
git push --tags

# Configure linesync to fetch it
docker run ... -e CERT_TAG=myserver-cert linesync sync
```

## Security Considerations

- The Docker socket mount grants significant privileges. The container can control other containers.
- Use read-only deploy keys in your git repository
- Consider running the sidecar with `--read-only` filesystem (with tmpfs for `/tmp`)
- SSH keys should be stored in a named volume or secrets manager

## UID/GID Remapping

The container uses [fixuid](https://github.com/boxboat/fixuid) to automatically remap the internal user's UID/GID to match yours at runtime. This ensures files created in bind-mounted directories are owned by your host user.

**How it works:**
1. You specify `user: "${UID}:${GID}"` in docker-compose (or `-u "$(id -u):$(id -g)"` on command line)
2. fixuid runs at container startup and remaps the `linesync` user to match
3. All file operations use your host UID/GID

**Without UID/GID mapping:** Files would be owned by UID 1234 (the container's default), causing permission issues.

## Troubleshooting

### "SSH key not found"
Run `keygen` mode first to generate keys, or mount existing keys to `/home/linesync/.ssh`.

### "SSH directory does not exist" or "not writable"
Create the directory on the host first:
```bash
mkdir -p ./linesync-ssh
```

### "Linesync repository not found"
Run `setup` mode first to clone the repository.

### "Could not signal container"
Ensure the Docker socket is mounted and the container name matches `NEFARIOUS_CONTAINER`.

### Permission denied on bind mounts
Make sure you're passing the UID/GID:
```bash
# Command line
docker run -u "$(id -u):$(id -g)" ...

# Docker compose
UID=$(id -u) GID=$(id -g) docker compose up
```

### Debug with shell access
```bash
docker run --rm -it -u "$(id -u):$(id -g)" \
  -v ./linesync-ssh:/home/linesync/.ssh \
  -v ./local.conf:/home/linesync/ircd/local.conf \
  -v ./linesync:/home/linesync/ircd/linesync \
  linesync shell
```
