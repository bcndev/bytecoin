#Use Fedora 28 docker image
FROM fedora

RUN dnf -y update && dnf -y install make  gcc-c++ cmake git wget libzip bzip2 which openssl-devel

WORKDIR /app

## Boost
ARG BOOST_VERSION=1_67_0
ARG BOOST_VERSION_DOT=1.67.0
ARG BOOST_HASH=2684c972994ee57fc5632e03bf044746f6eb45d4920c343937a465fd67a5adba
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
    && dnf remove -y make  gcc-c++ cmake git wget openssl-devel \
    && dnf install libstdc++ -y \
    && dnf clean all \
    && rm -rf /app \
    && echo '[ SHOW VERSION ]' \
    && bytecoind -v

