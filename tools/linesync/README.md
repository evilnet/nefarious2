# Linesync Sidecar Container

A Docker sidecar container for automated git-based configuration synchronization with Nefarious IRCd. This container periodically pulls configuration updates from a git repository and signals the IRCd to reload.

## Features

- Git-based configuration sync using SSH authentication
- Automatic SIGHUP signaling to nefarious container when config changes
- Configurable sync interval
- Support for SSL certificate sync via git tags
- Multiple operation modes: keygen, setup, sync, once
- Automatic UID/GID detection from bind mounts (no manual configuration needed)

## Quick Start

### 1. Build the container

```bash
cd tools/linesync
docker build -t linesync .
```

### 2. Create directories and generate SSH keys

```bash
mkdir -p ./linesync-ssh ./linesync
docker run --rm \
  -v ./linesync-ssh:/home/linesync/.ssh \
  linesync keygen
```

This outputs a public key. Add it to your git repository's deploy keys.

### 3. Initial repository setup

```bash
docker run --rm \
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

### Generate SSH keypair

```bash
mkdir -p ./linesync-ssh

# Generate ed25519 key (default, recommended)
docker run --rm \
  -v ./linesync-ssh:/home/linesync/.ssh \
  linesync keygen

# Generate RSA key
docker run --rm \
  -v ./linesync-ssh:/home/linesync/.ssh \
  linesync keygen rsa
```

### Initial setup (clone repository)

```bash
mkdir -p ./linesync
docker run --rm \
  -v ./linesync-ssh:/home/linesync/.ssh \
  -v ./local.conf:/home/linesync/ircd/local.conf \
  -v ./linesync:/home/linesync/ircd/linesync \
  -e GIT_REPOSITORY=git@github.com:yourorg/linesync-data.git \
  linesync setup
```

### Run sync once

```bash
docker run --rm \
  -v ./linesync-ssh:/home/linesync/.ssh \
  -v ./local.conf:/home/linesync/ircd/local.conf \
  -v ./linesync:/home/linesync/ircd/linesync \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e IRCD_CONF=/home/linesync/ircd/local.conf \
  linesync once
```

### Interactive shell (debugging)

```bash
docker run --rm -it \
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
docker compose run --rm linesync keygen

# 2. Add the public key to your git repo's deploy keys

# 3. Clone the linesync repository
docker compose run --rm \
  -e GIT_REPOSITORY=git@github.com:yourorg/linesync-data.git \
  linesync setup

# 4. Start the services
docker compose up -d
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
- SSH keys should be stored securely

## UID/GID Auto-Detection

The container automatically detects the UID/GID of your bind-mounted directories and runs as that user. This means files created by the container will be owned by your host user without any manual configuration.

**How it works:**
1. Container starts as root
2. Entrypoint detects the owner of mounted directories (e.g., `./linesync-ssh`)
3. Modifies the internal `linesync` user to match that UID/GID
4. Drops privileges and runs the actual command as that user

This happens automatically - no `-u` flags or environment variables needed.

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

### Debug with shell access
```bash
docker run --rm -it \
  -v ./linesync-ssh:/home/linesync/.ssh \
  -v ./local.conf:/home/linesync/ircd/local.conf \
  -v ./linesync:/home/linesync/ircd/linesync \
  linesync shell
```
