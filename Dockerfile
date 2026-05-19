# --- libkc: pulled from GHCR by default; override LIBKC_IMAGE to redirect ---
# Forks: --build-arg LIBKC_IMAGE=ghcr.io/<your-org>/libkc:<tag>
# Local dev: --build-context libkc=docker-image://local/libkc:dev (shadows this)
# Declared before any FROM so the value is in global scope and can be used
# in `FROM ${LIBKC_IMAGE}` below.
ARG LIBKC_IMAGE=ghcr.io/evilnet/libkc:sha-10aa335

FROM debian:13 AS base

ENV GID=1234
ENV UID=1234

# Single merged apt-get layer + ccache.  librocksdb-dev pulls in the
# Debian 13 build (8.x), the only storage backend.
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get -y install \
      build-essential ccache libssl-dev autoconf automake flex \
      byacc gawk git vim procps net-tools iputils-ping bind9-host \
      libzstd-dev libcmocka-dev valgrind libcurl4-openssl-dev libjansson-dev \
      libmaxminddb-dev libgeoip-dev pkg-config \
      libtool cmake nodejs npm \
      librocksdb-dev \
      libgit2-dev openssh-client && \
    rm -rf /var/lib/apt/lists/*

FROM ${LIBKC_IMAGE} AS libkc

# --- Merge libraries into base ---

FROM base AS libs
# Copy with /. trailing form so the libkc.so→libkc.so.0.0.0 symlink chain
# is preserved (a glob like /usr/lib/libkc* dereferences and we'd end up
# with three identical .so files instead of two symlinks + one real lib).
COPY --from=libkc /usr/lib/.     /usr/lib/
COPY --from=libkc /usr/include/. /usr/include/
RUN ldconfig

# --- Configure stage: only invalidated by autotools input changes ---

FROM libs AS configure

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

# Regenerate configure from configure.in.  The committed `configure` may
# be stale relative to configure.in changes; autoreconf produces a fresh
# configure that matches the current configure.in.
RUN autoreconf -fi

# MaxMindDB via pkg-config (handles Debian multiarch automatically).
# Legacy GeoIP enabled as fallback — Debian ships free GeoLiteCountry .dat files.
RUN ./configure --prefix=/home/nefarious --libdir=/home/nefarious/ircd --enable-debug \
      --with-maxcon=4096 --with-rocksdb=/usr --with-zstd=/usr --enable-keycloak \
      --with-geoip=/usr

# --- Build stage: ccache makes incremental rebuilds fast ---

FROM configure AS build

# Copy all remaining source (this layer busts on any .c/.h change)
COPY . /home/nefarious/nefarious2

# .release is generated before docker build (e.g. by CI) and needs to be in ircd/ where version.c.SH runs
RUN test -f .release && cp .release ircd/.release || true

# ccache via BuildKit cache mount — persists across docker builds
ENV PATH="/usr/lib/ccache:${PATH}"
RUN --mount=type=cache,target=/root/.ccache \
    make -j$(nproc)

# Run unit tests during build (they require the built object files).
# `make test` runs the legacy print-based tests; `make test-cmocka` runs
# the assertion-based cmocka suites (libcmocka-dev installed in the
# `libs` stage).  Both must pass for the build to succeed.
RUN --mount=type=cache,target=/root/.ccache \
    make test && (cd ircd/test && make cmocka && make test-cmocka)

# make install no longer auto-generates a cert (the makepem call was
# removed from ircd/Makefile.in — admins supply their own or run the
# tool manually).  Docker's entrypoint handles cert generation if the
# file is missing at container start.
RUN make install

# --- Build iauthd-ts (npm install cached unless package.json changes) ---

FROM libs AS build-iauthd
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

# --- Runtime stage ---

FROM libs AS runtime

RUN groupadd -g 1234 nefarious && \
    useradd -u 1234 -g 1234 nefarious && \
    mkdir -p /home/nefarious/ircd/history /home/nefarious/ircd/metadata \
             /home/nefarious/ircd/webpush /home/nefarious/ircd/cores && \
    chown -R nefarious:nefarious /home/nefarious

# Copy built ircd artifacts from build stage
COPY --from=build --chown=nefarious:nefarious /home/nefarious/ircd/ /home/nefarious/ircd/
COPY --from=build --chown=nefarious:nefarious /home/nefarious/bin/ /home/nefarious/bin/

# Copy iauthd-ts from its dedicated build stage
COPY --from=build-iauthd --chown=nefarious:nefarious /iauthd-ts-prod/ /home/nefarious/ircd/iauthd-ts/

# Symlink ircd.log to stdout so docker logs captures it
RUN ln -sf /dev/stdout /home/nefarious/ircd/ircd.log

# Install nodejs runtime (needed for iauthd-ts) + minimal runtime tools + GeoIP database.
# gdb included so post-mortem and live attach work via `docker exec` without
# sidecar timing races (sidecar pull/install can't catch a 30s startup window).
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get -y install --no-install-recommends nodejs openssl procps net-tools \
      geoip-database libmaxminddb0 libgeoip1t64 \
      gdb && \
    rm -rf /var/lib/apt/lists/*

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

# Run entrypoint (volume permissions fixed by init container in docker-compose)
ENTRYPOINT ["/home/nefarious/dockerentrypoint.sh"]

# Run IRCd in foreground with debug logging
# Set NEFARIOUS_VALGRIND=1 in environment to run under Valgrind
# Uses ircd.conf which includes local.conf (bind-mount your config there)
CMD ["/home/nefarious/bin/ircd", "-n", "-x", "5", "-f", "ircd.conf"]
