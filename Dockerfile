# build stage
FROM ubuntu:16.04 AS builder
MAINTAINER Mihail Fedorov <kolo@komodoplatform.com>

RUN apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install libcurl4-openssl-dev g++-multilib curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# We should keep everything above this comment matching
# identically with the start of the final image recipe, below.
# Keeping these two bits in sync will cause the base of the
# final image to get cached, saving both disk space and time.

RUN apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install build-essential pkg-config libc6-dev m4 autoconf libtool ncurses-dev \
    unzip python zlib1g-dev wget bsdmainutils automake libssl-dev libprotobuf-dev \
    protobuf-compiler libqrencode-dev libdb++-dev software-properties-common && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY ./ /komodo
ENV HOME /komodo
WORKDIR /komodo

# configure || true or it WILL halt
RUN cd /komodo && \
    ./autogen.sh && \
    ./configure --with-incompatible-bdb --with-gui || true && \
    ./zcutil/build.sh -j$(nproc) && \
    mv /komodo/src/verus /usr/local/bin/ && \
    mv /komodo/src/verusd /usr/local/bin/ && \
    mv /komodo/zcutil/docker-entrypoint.sh /usr/local/bin/ && \
    mv /komodo/zcutil/fetch-params.sh /usr/local/bin/ && \
    cd / && rm -rf /komodo

# final image
FROM ubuntu:16.04
MAINTAINER Mihail Fedorov <kolo@komodoplatform.com>

RUN apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install libcurl4-openssl-dev g++-multilib curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Base of final image (above) already built and cached in the build stage.

RUN curl -sL https://deb.nodesource.com/setup_8.x | bash - && \
    apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install nodejs && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=builder /usr/local/bin/verus /usr/bin/
COPY --from=builder /usr/local/bin/verusd /usr/bin/
COPY --from=builder /usr/local/bin/docker-entrypoint.sh /usr/bin/entrypoint
COPY --from=builder /usr/local/bin/fetch-params.sh /usr/bin/fetch-params

CMD ["entrypoint"]
