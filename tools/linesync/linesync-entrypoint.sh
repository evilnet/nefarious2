#!/bin/bash
# Linesync Sidecar Entrypoint
# Supports multiple modes of operation for configuration synchronization

set -e

# Configuration with defaults
: "${SYNC_INTERVAL:=300}"           # Sync interval in seconds (default: 5 minutes)
: "${IRCD_CONF:=/home/linesync/ircd/ircd.conf}"
: "${IRCD_PID:=/home/linesync/ircd/ircd.pid}"
: "${SSH_KEY:=/home/linesync/.ssh/id_ed25519}"
: "${NEFARIOUS_CONTAINER:=nefarious}"
: "${GIT_REPOSITORY:=}"
: "${CERT_TAG:=}"

GITSYNC="/home/linesync/gitsync.sh"

show_help() {
    echo "Linesync Sidecar Container"
    echo ""
    echo "Modes:"
    echo "  keygen              Generate a new SSH keypair for git authentication"
    echo "  setup               Clone the linesync git repository (initial setup)"
    echo "  sync                Run continuous sync loop (default)"
    echo "  once                Run sync once and exit"
    echo "  shell               Start an interactive shell"
    echo "  help                Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  SYNC_INTERVAL       Seconds between sync attempts (default: 300)"
    echo "  IRCD_CONF           Path to ircd.conf (default: /home/linesync/ircd/ircd.conf)"
    echo "  IRCD_PID            Path to ircd.pid (default: /home/linesync/ircd/ircd.pid)"
    echo "  SSH_KEY             Path to SSH private key (default: /home/linesync/.ssh/id_ed25519)"
    echo "  NEFARIOUS_CONTAINER Name of nefarious container to signal (default: nefarious)"
    echo "  GIT_REPOSITORY      Git repository URL (required for setup mode)"
    echo "  CERT_TAG            Git tag for SSL certificate (optional)"
    echo ""
    echo "Volume Mounts:"
    echo "  /home/linesync/.ssh         SSH keys directory"
    echo "  /home/linesync/ircd         IRCd config directory (shared with nefarious)"
    echo "  /var/run/docker.sock        Docker socket (for sending SIGHUP)"
    echo ""
}

# Generate SSH keypair
do_keygen() {
    local keytype="${1:-ed25519}"
    local sshdir="/home/linesync/.ssh"
    local keyfile="${sshdir}/id_${keytype}"

    # Check if .ssh directory exists
    if [ ! -d "$sshdir" ]; then
        echo "Error: SSH directory $sshdir does not exist"
        echo "Create the directory on the host first: mkdir -p ./linesync-ssh"
        exit 1
    fi

    # Check if directory is writable
    if [ ! -w "$sshdir" ]; then
        echo "Error: SSH directory $sshdir is not writable"
        echo "Fix permissions on the host: chmod 700 ./linesync-ssh && chown $(id -u):$(id -g) ./linesync-ssh"
        exit 1
    fi

    # Ensure proper directory permissions
    chmod 700 "$sshdir" 2>/dev/null || true

    if [ -f "$keyfile" ]; then
        echo "Key already exists at $keyfile"
        echo "Public key:"
        cat "${keyfile}.pub"
        return 0
    fi

    echo "Generating ${keytype} keypair..."
    ssh-keygen -t "$keytype" -f "$keyfile" -N "" -C "linesync@$(hostname)"

    # Set proper permissions on the key files
    chmod 600 "$keyfile"
    chmod 644 "${keyfile}.pub"

    echo ""
    echo "Key generated successfully!"
    echo ""
    echo "Public key (add this to your git repository's deploy keys):"
    echo "================================================================"
    cat "${keyfile}.pub"
    echo "================================================================"
}

# Initial repository setup
do_setup() {
    if [ -z "$GIT_REPOSITORY" ]; then
        echo "Error: GIT_REPOSITORY environment variable is required for setup"
        exit 1
    fi

    if [ ! -f "$SSH_KEY" ]; then
        echo "Error: SSH key not found at $SSH_KEY"
        echo "Run 'keygen' mode first to create a keypair"
        exit 1
    fi

    echo "Setting up linesync repository..."
    echo "Repository: $GIT_REPOSITORY"
    echo "SSH Key: $SSH_KEY"
    echo "Config: $IRCD_CONF"

    # Run gitsync.sh in setup mode
    "$GITSYNC" -s "$SSH_KEY" -i "$GIT_REPOSITORY" "$IRCD_CONF" "$IRCD_PID"
}

# Signal nefarious container to reload config
signal_reload() {
    if [ -S /var/run/docker.sock ]; then
        echo "Sending SIGHUP to container: $NEFARIOUS_CONTAINER"
        docker kill --signal=SIGHUP "$NEFARIOUS_CONTAINER" 2>/dev/null || \
            echo "Warning: Could not signal container (may not be running)"
    else
        echo "Warning: Docker socket not available, cannot signal container"
        echo "Config changes will take effect on next ircd restart"
    fi
}

# Run a single sync
do_sync_once() {
    local sync_args="-s $SSH_KEY"

    if [ -n "$CERT_TAG" ]; then
        sync_args="$sync_args -c $CERT_TAG"
    fi

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Running sync..."

    # Create a wrapper that signals via docker instead of using PID file
    # We'll run gitsync.sh but handle the signaling ourselves
    local tmp_pid="/tmp/fake.pid"
    echo "99999" > "$tmp_pid"

    # Capture gitsync output to check if changes were made
    local before_md5=""
    local after_md5=""

    if [ -f "$IRCD_CONF" ]; then
        before_md5=$(md5sum "$IRCD_CONF" 2>/dev/null | cut -d' ' -f1)
    fi

    # Run gitsync (it will try to HUP pid 99999 which will fail silently)
    "$GITSYNC" $sync_args "$IRCD_CONF" "$tmp_pid" 2>&1 || true

    if [ -f "$IRCD_CONF" ]; then
        after_md5=$(md5sum "$IRCD_CONF" 2>/dev/null | cut -d' ' -f1)
    fi

    # If config changed, signal the container
    if [ "$before_md5" != "$after_md5" ] && [ -n "$after_md5" ]; then
        echo "Configuration changed, signaling reload..."
        signal_reload
    fi

    rm -f "$tmp_pid"
}

# Continuous sync loop
do_sync_loop() {
    echo "Starting linesync daemon"
    echo "Sync interval: ${SYNC_INTERVAL}s"
    echo "Config: $IRCD_CONF"
    echo "Container: $NEFARIOUS_CONTAINER"
    echo ""

    # Check prerequisites
    if [ ! -f "$SSH_KEY" ]; then
        echo "Error: SSH key not found at $SSH_KEY"
        echo "Run 'keygen' mode first, or mount your key"
        exit 1
    fi

    local linesync_dir
    linesync_dir=$(dirname "$IRCD_CONF")/linesync

    if [ ! -d "$linesync_dir" ]; then
        echo "Error: Linesync repository not found at $linesync_dir"
        echo "Run 'setup' mode first to clone the repository"
        exit 1
    fi

    # Main loop
    while true; do
        do_sync_once
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Sleeping ${SYNC_INTERVAL}s..."
        sleep "$SYNC_INTERVAL"
    done
}

# Main entrypoint
case "${1:-sync}" in
    keygen)
        do_keygen "${2:-ed25519}"
        ;;
    setup)
        do_setup
        ;;
    sync)
        do_sync_loop
        ;;
    once)
        do_sync_once
        ;;
    shell|bash|sh)
        exec /bin/bash
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
