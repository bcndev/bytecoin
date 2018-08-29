# Use Fedora 28 docker image
# Multistage docker build, requires docker 17.05
FROM fedora:28 as builder

# If you have an old version of the docker, then
# correct the previous line, it should be the
# FROM fedora

RUN dnf -y update && dnf -y install make  gcc-c++ cmake git wget libzip bzip2 which openssl-devel

WORKDIR /app

## Boost
ARG BOOST_VERSION=1_68_0
ARG BOOST_VERSION_DOT=1.68.0
ARG BOOST_HASH=7f6130bc3cf65f56a618888ce9d5ea704fa10b462be126ad053e80e553d6d8b7
RUN set -ex \
    && curl -s -L -o  boost_${BOOST_VERSION}.tar.bz2 https://dl.bintray.com/boostorg/release/${BOOST_VERSION_DOT}/source/boost_${BOOST_VERSION}.tar.bz2 \
    && echo "${BOOST_HASH} boost_${BOOST_VERSION}.tar.bz2" | sha256sum -c \
    && tar -xvf boost_${BOOST_VERSION}.tar.bz2 \
    && mv boost_${BOOST_VERSION} boost \
    && cd boost \
    && ./bootstrap.sh \
    && ./b2 --build-type=minimal link=static -j4 runtime-link=static --with-chrono --with-date_time --with-filesystem --with-program_options --with-regex --with-serialization --with-system --with-thread --stagedir=stage threading=multi threadapi=pthread cflags="-fPIC" cxxflags="-fPIC" stage

# LMDB
ARG LMDB_VERSION=LMDB_0.9.22
ARG LMDB_HASH=5033a08c86fb6ef0adddabad327422a1c0c0069a
RUN set -ex \
    && git clone https://github.com/LMDB/lmdb.git -b ${LMDB_VERSION} \
    && cd lmdb \
    && test `git rev-parse HEAD` = ${LMDB_HASH} || exit 1

COPY . /app/bytecoin

RUN set -ex \
    && mkdir /app/bytecoin/build \
    && cd bytecoin/build \
    && cmake .. \
    && time make -j4 \
    && cp -v ../bin/* /usr/local/bin \
    && mkdir /usr/local/bin/wallet_file \
    && cp -v ../tests/wallet_file/* /usr/local/bin/wallet_file \
    && dnf remove -y make  gcc-c++ cmake git wget openssl-devel \
    && dnf install libstdc++ -y \
    && dnf clean all \
    && rm -rf /app \
    && echo '[ SHOW VERSION ]' \
    && bytecoind -v

# If you have an old version of the docker:
# (not supported Multistage docker build)
# Please comment all the lines below this!

FROM fedora:28

RUN set -ex \
    && dnf update -y \
    && dnf install libstdc++ -y \
    && dnf clean all

COPY --from=builder /usr/local/bin/* /usr/local/bin/

RUN ls -la /usr/local/bin/ \
    && mkdir -p /tests/wallet_file \
    && cp /usr/local/bin/*.wallet /tests/wallet_file/ \
    && cd /tests && tests || : \
    && echo '[ SHOW VERSION ]' \
    && bytecoind -v
