FROM debian:12

ENV GID 1234
ENV UID 1234

RUN DEBIAN_FRONTEND=noninteractive RUNLEVEL=1 apt-get update 
RUN DEBIAN_FRONTEND=noninteractive RUNLEVEL=1 apt-get update && apt-get -y install build-essential libssl-dev autoconf automake flex libpcre3-dev byacc gawk git libgeoip-dev libmaxminddb-dev vim

RUN mkdir -p /home/nefarious/nefarious2
RUN mkdir -p /home/nefarious/ircd
COPY . /home/nefarious/nefarious2
COPY ./tools/docker/dockerentrypoint.sh /home/nefarious/dockerentrypoint.sh

RUN groupadd -g ${GID} nefarious
RUN useradd -u ${UID} -g ${GID} nefarious
RUN chown -R nefarious:nefarious /home/nefarious
USER nefarious

WORKDIR  /home/nefarious/nefarious2

#Build and install nefarious
# maxcon bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=578038 - docker build limit seems different than docker run limit
RUN ./configure --libdir=/home/nefarious/ircd --mandir=/home/nefarious/ircd --bindir=/home/nefarious/ircd \
-with-geoip=/usr --with-mmdb=/usr --enable-debug --with-maxcon=4096
RUN make
RUN touch /home/nefarious/ircd/ircd.pem && make install && rm /home/nefarious/ircd/ircd.pem

WORKDIR /home/nefarious/ircd

COPY tools/docker/base.conf /home/nefarious/ircd/base.conf

#Clean up build
#RUN rm -rf /home/nefarious/nefarious2

ENTRYPOINT ["/home/nefarious/dockerentrypoint.sh"]

CMD ["/home/nefarious/ircd/ircd", "-n"]
