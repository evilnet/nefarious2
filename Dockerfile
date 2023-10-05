FROM debian:12

RUN DEBIAN_FRONTEND=noninteractive RUNLEVEL=1 apt-get update && apt-get -y install build-essential libssl-dev autoconf automake flex libpcre3-dev byacc gawk

RUN mkdir -p /data/nefarious2
COPY . /data/nefarious2

WORKDIR  /data/nefarious2
RUN ./configure --libdir=/data/ircd --mandir=/data/ircd --bindir=/data/ircd
RUN make
RUN make install
