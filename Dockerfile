FROM debian:12

ENV GID 1234
ENV UID 1234

RUN DEBIAN_FRONTEND=noninteractive RUNLEVEL=1 apt-get update
RUN DEBIAN_FRONTEND=noninteractive RUNLEVEL=1 apt-get -y install build-essential libssl-dev autoconf automake flex libpcre3-dev byacc gawk git vim procps net-tools iputils-ping bind9-host libzstd-dev libcmocka-dev valgrind libcurl4-openssl-dev libjansson-dev libtool cmake
#libgeoip-dev libmaxminddb-dev

# Perl dependencies for iauthd.pl (commented out - using TypeScript version)
#RUN DEBIAN_FRONTEND=noninteractive apt-get -y install libpoe-perl libpoe-component-client-dns-perl libterm-readkey-perl libfile-slurp-perl libtime-duration-perl

# Node.js for iauthd-ts
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install nodejs npm

# Build and install libkc (shared Keycloak/HTTP library)
COPY --from=libkc . /tmp/libkc
WORKDIR /tmp/libkc
RUN autoreconf -fi && ./configure --prefix=/usr && make && make install && ldconfig
WORKDIR /

# Build and install libmdbx
COPY --from=libmdbx . /tmp/libmdbx
WORKDIR /tmp/libmdbx
RUN cmake -B build -DCMAKE_INSTALL_PREFIX=/usr -DMDBX_BUILD_TOOLS=OFF -DMDBX_BUILD_CXX=OFF && cmake --build build && cmake --install build && ldconfig
WORKDIR /

RUN mkdir -p /home/nefarious/nefarious2
RUN mkdir -p /home/nefarious/ircd

COPY . /home/nefarious/nefarious2

RUN groupadd -g ${GID} nefarious
RUN useradd -u ${UID} -g ${GID} nefarious
# Create database directories for chathistory and metadata storage
# Create cores directory for valgrind logs
RUN mkdir -p /home/nefarious/ircd/history /home/nefarious/ircd/metadata /home/nefarious/ircd/webpush /home/nefarious/ircd/cores
RUN chown -R nefarious:nefarious /home/nefarious
USER nefarious

WORKDIR  /home/nefarious/nefarious2

#Build and install nefarious
# maxcon bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=578038 - docker build limit seems different than docker run limit
#RUN ./configure --libdir=/home/nefarious/ircd --mandir=/home/nefarious/ircd --bindir=/home/nefarious/ircd \

# I cant get the maxminddb library to compile in at all in debian 12, give up on geoip for now
# --with-geoip=/usr --with-mmdb=/usr \
# Enable LMDB for chathistory and zstd for compression
RUN ./configure --libdir=/home/nefarious/ircd --enable-debug --with-maxcon=4096 --with-mdbx=/usr --with-zstd=/usr --enable-keycloak
RUN make
# Run unit tests during build (they require the built object files)
RUN make test
# make install runs an interactive SSL generator - pre-create pem to skip, then remove so entrypoint generates fresh one
RUN touch /home/nefarious/ircd/ircd.pem && make install && rm /home/nefarious/ircd/ircd.pem

# Build iauthd-ts
WORKDIR /home/nefarious/nefarious2/tools/iauthd-ts
RUN npm install && npm run build

# Copy iauthd-ts to ircd directory
RUN cp -r /home/nefarious/nefarious2/tools/iauthd-ts/dist /home/nefarious/ircd/iauthd-ts
RUN cp /home/nefarious/nefarious2/tools/iauthd-ts/package.json /home/nefarious/ircd/iauthd-ts/
WORKDIR /home/nefarious/ircd/iauthd-ts
RUN npm install --omit=dev

WORKDIR /home/nefarious/ircd

# Symlink ircd.log to stdout so docker logs captures it
RUN ln -sf /dev/stdout /home/nefarious/ircd/ircd.log

USER root
#Clean up build
RUN rm -rf /home/nefarious/nefarious2 /tmp/libkc /tmp/libmdbx
RUN apt-get remove -y build-essential && apt-get autoremove -y && apt-get clean

USER nefarious

COPY ./tools/docker/dockerentrypoint.sh /home/nefarious/dockerentrypoint.sh
COPY ./tools/linesync/gitsync.sh /home/nefarious/ircd/gitsync.sh

# Create wrapper script for iauthd.pl that runs the Node.js version
RUN printf '#!/bin/sh\nexec node /home/nefarious/ircd/iauthd-ts/index.js "$@"\n' > /home/nefarious/ircd/iauthd.pl && \
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



