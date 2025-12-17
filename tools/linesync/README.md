# Linesync

Git-based configuration sync for Nefarious IRCd. Pulls config updates from a git repository and sends SIGHUP to reload.

## Using Docker Compose

Add linesync to your `docker-compose.yml`:

```yaml
services:
  nefarious:
    image: ghcr.io/evilnet/nefarious2:latest
    container_name: nefarious
    volumes:
      - ./local.conf:/home/nefarious/ircd/local.conf
    ports:
      - "6667:6667"

  linesync:
    image: ghcr.io/evilnet/nefarious2-linesync:latest
    depends_on:
      - nefarious
    volumes:
      - ./linesync-ssh:/home/linesync/.ssh
      - ./local.conf:/home/linesync/ircd/local.conf
      - ./linesync:/home/linesync/ircd/linesync
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      NEFARIOUS_CONTAINER: nefarious
      SYNC_INTERVAL: 300
      IRCD_CONF: /home/linesync/ircd/local.conf
```

### Setup

```bash
# Create directories
mkdir -p ./linesync-ssh ./linesync
touch ./local.conf

# Generate SSH key
docker compose run --rm linesync keygen

# Add the printed public key to your git repo's deploy keys

# Clone the linesync repo
docker compose run --rm -e GIT_REPOSITORY=git@github.com:yourorg/linesync-data.git linesync setup

# Start services
docker compose up -d
```

### Manual sync

```bash
docker compose run --rm linesync once
```

---

## Using Standalone Docker

### Setup

```bash
# Build
cd tools/linesync
docker build -t linesync .

# Create directories
mkdir -p ./linesync-ssh ./linesync
touch ./local.conf

# Generate SSH key
docker run --rm -v ./linesync-ssh:/home/linesync/.ssh linesync keygen

# Add the printed public key to your git repo's deploy keys

# Clone the linesync repo
docker run --rm \
  -v ./linesync-ssh:/home/linesync/.ssh \
  -v ./local.conf:/home/linesync/ircd/local.conf \
  -v ./linesync:/home/linesync/ircd/linesync \
  -e GIT_REPOSITORY=git@github.com:yourorg/linesync-data.git \
  linesync setup
```

### Run continuous sync

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

### Run once

```bash
docker run --rm \
  -v ./linesync-ssh:/home/linesync/.ssh \
  -v ./local.conf:/home/linesync/ircd/local.conf \
  -v ./linesync:/home/linesync/ircd/linesync \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e IRCD_CONF=/home/linesync/ircd/local.conf \
  linesync once
```

### Debug shell

```bash
docker run --rm -it \
  -v ./linesync-ssh:/home/linesync/.ssh \
  -v ./local.conf:/home/linesync/ircd/local.conf \
  -v ./linesync:/home/linesync/ircd/linesync \
  linesync shell
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GIT_REPOSITORY` | — | Git repo URL (required for setup) |
| `NEFARIOUS_CONTAINER` | `nefarious` | Container to send SIGHUP |
| `SYNC_INTERVAL` | `300` | Seconds between syncs |
| `IRCD_CONF` | `/home/linesync/ircd/ircd.conf` | Config file path |
| `CERT_TAG` | — | Git tag for SSL cert sync |
| `CERT_FILE` | `fullchain.pem` | Output path for synced certificate |

## Config File Format

Your git repository needs a `linesync.data` file with IRC config blocks. These get inserted into your config between markers:

```
# BEGIN LINESYNC
... (managed by linesync) ...
# END LINESYNC
```

Markers are added automatically on first sync.

## SSL Certificate Sync

Store certs in git tags:

```bash
git tag -f myserver-cert $(cat fullchain.pem | git hash-object -w --stdin)
git push origin :refs/tags/myserver-cert
git push --tags
```

Then set `CERT_TAG=myserver-cert` in your environment. To write to a specific file (e.g., `ircd.pem`), also set `CERT_FILE=/home/linesync/ircd/ircd.pem`.

## Notes

- UID/GID is auto-detected from bind mounts — files will be owned by your host user
- Docker socket access grants container control privileges
- Use read-only deploy keys
