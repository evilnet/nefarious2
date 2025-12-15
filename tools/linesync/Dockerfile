# Linesync Sidecar Container
# Provides git-based configuration synchronization for Nefarious IRCd
#
# Supports three modes:
#   keygen  - Generate SSH keypair for git authentication
#   setup   - Clone the linesync repository (initial setup)
#   sync    - Continuous sync loop (default)

FROM debian:12-slim

ENV GID=1234
ENV UID=1234

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
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI (for sending signals to nefarious container)
RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Create user matching nefarious container
RUN groupadd -g ${GID} linesync \
    && useradd -u ${UID} -g ${GID} -m linesync

# Create directories
RUN mkdir -p /home/linesync/.ssh \
    && mkdir -p /home/linesync/ircd \
    && chown -R linesync:linesync /home/linesync

# Copy scripts
COPY gitsync.sh /home/linesync/gitsync.sh
COPY linesync-entrypoint.sh /home/linesync/entrypoint.sh
RUN chmod +x /home/linesync/gitsync.sh /home/linesync/entrypoint.sh

USER linesync
WORKDIR /home/linesync

# SSH config for git
RUN echo "Host *\n  StrictHostKeyChecking accept-new\n  UserKnownHostsFile /home/linesync/.ssh/known_hosts" > /home/linesync/.ssh/config \
    && chmod 600 /home/linesync/.ssh/config

ENTRYPOINT ["/home/linesync/entrypoint.sh"]
CMD ["sync"]
