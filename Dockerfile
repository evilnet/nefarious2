FROM debian:12

ENV GID 1234
ENV UID 1234

RUN DEBIAN_FRONTEND=noninteractive RUNLEVEL=1 apt-get update 
RUN DEBIAN_FRONTEND=noninteractive RUNLEVEL=1 apt-get update && apt-get -y install build-essential libssl-dev autoconf automake flex libpcre3-dev byacc gawk git vim libpoe-perl libpoe-component-client-dns-perl libterm-readkey-perl libfile-slurp-perl libtime-duration-perl procps net-tools
#libgeoip-dev libmaxminddb-dev 

RUN mkdir -p /home/nefarious/nefarious2
RUN mkdir -p /home/nefarious/ircd
COPY . /home/nefarious/nefarious2
COPY ./tools/docker/dockerentrypoint.sh /home/nefarious/dockerentrypoint.sh
COPY ./tools/linesync/gitsync.sh /home/nefarious/ircd/gitsync.sh
COPY ./tools/iauthd.pl /home/nefarious/ircd/iauthd.pl

#This ircd.conf just includes the other 3
COPY tools/docker/ircd.conf /home/nefarious/ircd/ircd.conf
COPY tools/docker/base.conf-dist /home/nefarious/ircd/base.conf-dist
COPY tools/docker/local.conf /home/nefarious/ircd/local.conf
COPY tools/docker/linesync.conf /home/nefarious/ircd/linesync.conf


RUN groupadd -g ${GID} nefarious
RUN useradd -u ${UID} -g ${GID} nefarious
RUN chown -R nefarious:nefarious /home/nefarious
USER nefarious

WORKDIR  /home/nefarious/nefarious2

#Build and install nefarious
# maxcon bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=578038 - docker build limit seems different than docker run limit
#RUN ./configure --libdir=/home/nefarious/ircd --mandir=/home/nefarious/ircd --bindir=/home/nefarious/ircd \

# I cant get the maxminddb library to compile in at all in debian 12, give up on geoip for now
# --with-geoip=/usr --with-mmdb=/usr \
RUN ./configure --libdir=/home/nefarious/ircd --enable-debug --with-maxcon=4096
RUN make
RUN touch /home/nefarious/ircd/ircd.pem && make install && rm /home/nefarious/ircd/ircd.pem

WORKDIR /home/nefarious/ircd

USER root
#Clean up build
RUN rm -rf /home/nefarious/nefarious2
RUN apt-get remove -y build-essential && apt-get autoremove -y
RUN apt-get clean

USER nefarious

ENTRYPOINT ["/home/nefarious/dockerentrypoint.sh"]

CMD ["/home/nefarious/bin/ircd", "-n", "-x", "9"]



