# Linesync Sidecar Container
# Provides git-based configuration synchronization for Nefarious IRCd
#
# Supports three modes:
#   keygen  - Generate SSH keypair for git authentication
#   setup   - Clone the linesync repository (initial setup)
#   sync    - Continuous sync loop (default)
#
# Automatically detects UID/GID from mounted directories for proper permissions.

FROM debian:12-slim

# Default UID/GID (will be overridden at runtime based on mounted directory ownership)
ENV LINESYNC_UID=1000
ENV LINESYNC_GID=1000

# Install required tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    git \
    gawk \
    openssh-client \
    openssl \
    ca-certificates \
    curl \
    gnupg \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI (for sending signals to nefarious container)
RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Create user (UID/GID will be adjusted at runtime)
RUN groupadd -g ${LINESYNC_GID} linesync \
    && useradd -u ${LINESYNC_UID} -g ${LINESYNC_GID} -m linesync

# Create directories
RUN mkdir -p /home/linesync/.ssh \
    && mkdir -p /home/linesync/ircd \
    && chown -R linesync:linesync /home/linesync

# Copy scripts
COPY gitsync.sh /home/linesync/gitsync.sh
COPY linesync-entrypoint.sh /home/linesync/entrypoint.sh
RUN chmod +x /home/linesync/gitsync.sh /home/linesync/entrypoint.sh

# SSH config template (will be copied to user's .ssh at runtime)
RUN echo "Host *\n  StrictHostKeyChecking accept-new\n  UserKnownHostsFile /home/linesync/.ssh/known_hosts" > /etc/ssh/ssh_config.d/linesync.conf

WORKDIR /home/linesync

# Run as root initially; entrypoint will drop privileges after detecting UID/GID
ENTRYPOINT ["/home/linesync/entrypoint.sh"]
CMD ["sync"]
