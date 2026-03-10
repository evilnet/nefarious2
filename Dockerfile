FROM debian:13 AS base

ENV GID=1234
ENV UID=1234

# Single consolidated apt-get layer + ccache
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get -y install \
      build-essential ccache libssl-dev autoconf automake flex \
      byacc gawk git vim procps net-tools iputils-ping bind9-host \
      libmaxminddb-dev libgeoip-dev pkg-config \
      nodejs npm && \
    rm -rf /var/lib/apt/lists/*

# --- Configure stage: only invalidated by autotools input changes ---

FROM base AS configure

RUN mkdir -p /home/nefarious/nefarious2/ircd /home/nefarious/nefarious2/ircd/test /home/nefarious/ircd
WORKDIR /home/nefarious/nefarious2

# Copy ONLY the files configure needs — source changes won't bust this cache
COPY configure.in acinclude.m4 aclocal.m4 configure install-sh config.guess config.sub ./
COPY config.h.in ./
COPY Makefile.in ./
COPY ircd/Makefile.in ./ircd/
COPY ircd/test/Makefile.in ./ircd/test/
COPY include/ ./include/

# AC_INIT(ircd/ircd.c) sanity check — touch instead of COPY to avoid cache bust on source changes
RUN touch ircd/ircd.c

# GeoIP re-enabled — Debian 13 ships working libmaxminddb + legacy GeoIP
RUN ./configure --prefix=/home/nefarious --libdir=/home/nefarious/ircd --enable-debug \
      --with-maxcon=4096 --with-geoip=/usr

# --- Build stage: ccache makes incremental rebuilds fast ---

FROM configure AS build

# Copy all remaining source (this layer busts on any .c/.h change)
COPY . /home/nefarious/nefarious2

# ccache via BuildKit cache mount — persists across docker builds
ENV PATH="/usr/lib/ccache:${PATH}"
RUN --mount=type=cache,target=/root/.ccache \
    make -j$(nproc)

# make install runs an interactive SSL generator - pre-create pem to skip, then remove so entrypoint generates fresh one
RUN touch /home/nefarious/ircd/ircd.pem && make install && \
    rm /home/nefarious/ircd/ircd.pem

# --- Build iauthd-ts (npm install cached unless package.json changes) ---

FROM base AS build-iauthd
WORKDIR /iauthd-ts

# Copy only dependency manifests first — npm ci cached until these change
COPY tools/iauthd-ts/package.json tools/iauthd-ts/package-lock.json ./
RUN npm ci

# Now copy source and build — only this layer busts on .ts changes
COPY tools/iauthd-ts/ ./
RUN npm run build

# Prepare production install
RUN mkdir -p /iauthd-ts-prod && \
    cp -r dist /iauthd-ts-prod/ && \
    cp package.json package-lock.json /iauthd-ts-prod/
WORKDIR /iauthd-ts-prod
RUN npm ci --omit=dev

# --- Runtime stage: clean image with only runtime dependencies ---

FROM debian:13 AS runtime

# Minimal runtime packages + GeoIP database + valgrind (opt-in via NEFARIOUS_VALGRIND=1)
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get -y install --no-install-recommends \
      nodejs openssl procps net-tools \
      geoip-database libmaxminddb0 libgeoip1t64 valgrind && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1234 nefarious && \
    useradd -u 1234 -g 1234 nefarious && \
    mkdir -p /home/nefarious/ircd /home/nefarious/ircd/cores && \
    chown -R nefarious:nefarious /home/nefarious

# Copy built ircd artifacts from build stage
COPY --from=build --chown=nefarious:nefarious /home/nefarious/ircd/ /home/nefarious/ircd/
COPY --from=build --chown=nefarious:nefarious /home/nefarious/bin/ /home/nefarious/bin/

# Copy iauthd-ts from its dedicated build stage
COPY --from=build-iauthd --chown=nefarious:nefarious /iauthd-ts-prod/ /home/nefarious/ircd/iauthd-ts/

# Symlink ircd.log to stdout so docker logs captures it
RUN ln -sf /dev/stdout /home/nefarious/ircd/ircd.log

USER nefarious
WORKDIR /home/nefarious/ircd

COPY ./tools/docker/dockerentrypoint.sh /home/nefarious/dockerentrypoint.sh
COPY ./tools/linesync/gitsync.sh /home/nefarious/ircd/gitsync.sh

# Create wrapper script for iauthd.pl that runs the Node.js version
RUN printf '#!/bin/sh\nexec node /home/nefarious/ircd/iauthd-ts/dist/index.js "$@"\n' > /home/nefarious/ircd/iauthd.pl && \
    chmod +x /home/nefarious/ircd/iauthd.pl

#ircd-docker.conf includes the other config files
COPY tools/docker/ircd-docker.conf /home/nefarious/ircd/ircd-docker.conf
COPY tools/docker/base.conf-dist /home/nefarious/ircd/base.conf-dist
COPY tools/docker/ircd.conf /home/nefarious/ircd/ircd.conf
COPY tools/docker/linesync.conf /home/nefarious/ircd/linesync.conf

ENTRYPOINT ["/home/nefarious/dockerentrypoint.sh"]

# Run IRCd in foreground with debug logging
# Set NEFARIOUS_VALGRIND=1 in environment to run under Valgrind
CMD ["/home/nefarious/bin/ircd", "-n", "-x", "5", "-f", "ircd-docker.conf"]
