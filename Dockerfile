FROM debian:13 AS base

ENV GID=1234
ENV UID=1234

# Single merged apt-get layer + ccache.  librocksdb-dev pulls in the
# Debian 13 build (8.x).  Both backends are available; the binary
# selects one at configure time via --with-storage-backend.
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

# --- Build libraries in parallel using multi-stage ---

FROM base AS build-libkc
COPY --from=libkc . /tmp/libkc
WORKDIR /tmp/libkc
RUN autoreconf -fi && ./configure --prefix=/usr && make -j$(nproc) && make install

FROM base AS build-libmdbx
COPY --from=libmdbx . /tmp/libmdbx
WORKDIR /tmp/libmdbx
RUN cmake -B build -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib \
      -DMDBX_BUILD_TOOLS=OFF -DMDBX_BUILD_CXX=OFF && \
    cmake --build build -j$(nproc) && cmake --install build

# --- Merge libraries into base ---

FROM base AS libs
COPY --from=build-libkc /usr/lib/libkc* /usr/lib/
COPY --from=build-libkc /usr/include/kc/ /usr/include/kc/
COPY --from=build-libmdbx /usr/lib/libmdbx* /usr/lib/
COPY --from=build-libmdbx /usr/include/mdbx.h /usr/include/
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
# be stale relative to configure.in changes (e.g. new --with-storage-backend
# option for the libmdbx → RocksDB migration).  autoreconf produces a
# fresh configure that matches the current configure.in.
RUN autoreconf -fi

# MaxMindDB via pkg-config (handles Debian multiarch automatically)
# Legacy GeoIP enabled as fallback — Debian ships free GeoLiteCountry .dat files
# Pass --build-arg STORAGE_BACKEND=rocksdb to build the RocksDB-flavoured
# binary; default stays mdbx so existing builds are unaffected.
ARG STORAGE_BACKEND=mdbx
RUN if [ "$STORAGE_BACKEND" = "rocksdb" ]; then \
      ROCKSDB_FLAGS="--enable-rocksdb --with-rocksdb=/usr"; \
    else \
      ROCKSDB_FLAGS=""; \
    fi && \
    ./configure --prefix=/home/nefarious --libdir=/home/nefarious/ircd --enable-debug \
      --with-maxcon=4096 --with-mdbx=/usr --with-zstd=/usr --enable-keycloak \
      $ROCKSDB_FLAGS \
      --with-geoip=/usr --with-storage-backend=${STORAGE_BACKEND}

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

# Run unit tests during build (they require the built object files)
RUN --mount=type=cache,target=/root/.ccache \
    make test

# make install runs an interactive SSL generator - pre-create pem to skip, then remove so entrypoint generates fresh one
RUN touch /home/nefarious/ircd/ircd.pem && make install && \
    rm /home/nefarious/ircd/ircd.pem

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

# Install nodejs runtime (needed for iauthd-ts) + minimal runtime tools + GeoIP database
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get -y install --no-install-recommends nodejs openssl procps net-tools \
      geoip-database libmaxminddb0 libgeoip1t64 && \
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
