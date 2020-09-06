FROM ubuntu:xenial AS system-setup

WORKDIR /build

RUN apt-get update -y && apt-get install -y wget software-properties-common
RUN apt-get update -y \
  && apt-get install -y \
    curl \
    g++ \
    clang-8 \
    automake \
    git \
    libtool \
    make \
    pkg-config \
    jq \
    libpcre3 \
    libpcre3-dev \
    libpcap-dev \
    libnet1-dev \
    libyaml-0-2 \
    libyaml-dev \
    zlib1g \
    zlib1g-dev \
    libcap-ng-dev \
    libcap-ng0 \
    libnss3-dev \
    libnspr4-dev \
    python \
    python-distutils-extra \
    python-setuptools \
    libgeoip1 \
    libgeoip-dev \
    libnetfilter-queue-dev \
    libnetfilter-queue1 \
    libjansson4 \
    libjansson-dev \
    python-simplejson \
    libnfnetlink-dev \
    libnfnetlink0 \
    libmagic-dev \
    libmagic1 \
    dh-autoreconf \
    libprelude-dev \
    liblua5.1-0-dev \
    build-essential \
    libssl-dev \
  && rm -rf /var/lib/apt || true

ENV RUST_BACKTRACE=1 \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

ARG RUST_VERSION=stable
RUN RUST_VERSION=$RUST_VERSION curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain $RUST_VERSION -y

RUN rustup component add --toolchain $RUST_VERSION rustfmt \
  && cargo install cargo-release \
  && cargo install --force cbindgen

FROM system-setup AS build-suricata

WORKDIR /build

#Checkout suricata
ARG SURICATA_VERSION=6.0.0
RUN SURICATA_VERSION=$SURICATA_VERSION git clone https://github.com/dbcfd/suricata

WORKDIR /build/suricata

RUN git pull && git checkout -b plugins-release origin/plugins-release

RUN git rev-parse --short HEAD

# libhtp stuffs here
RUN git clone https://github.com/ironbee/libhtp

RUN sh autogen.sh \
  && sh configure --prefix=/usr/ --sysconfdir=/etc/ --localstatedir=/var/ --enable-unix-socket --enable-pcre-jit \
  --with-libpcre-includes=/usr/local/include --with-libpcre-libraries=/usr/lib --disable-gccmarch-native \
  && make \
  && make install \
  && make install-conf

RUN /usr/bin/suricata -V

ENV SURICATA_EXE=/usr/bin/suricata \
  SURICATA_SRC_DIR=/build/suricata

FROM build-suricata AS development

ENV RUST_LOG=suricata_rs=debug

WORKDIR /development

VOLUME ["/development"]

ENTRYPOINT ["/bin/bash"]

FROM development AS build-plugin

#Xenial needs a new version of cmake (3.18.2)

RUN sudo apt-get update \
    && apt-get install apt-transport-https ca-certificates gnupg software-properties-common wget \
    && wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null \
    && apt-add-repository 'deb https://apt.kitware.com/ubuntu/ xenial main' \
    && apt-get update \
    && apt-get install -y cmake


#RUN apt-get update && apt-get install -y cmake

ADD /ipc-plugin ipc-plugin

WORKDIR /development/ipc-plugin

RUN cmake -S . -B ./build \
  && cd /development/ipc-plugin/build \
  && ls \
  && make gen-header \
  && make \
  && make install

FROM build-plugin AS build

WORKDIR /development

ADD /benches benches
ADD /resources resources
ADD /src src
ADD /templates templates
ADD /tests tests
ADD /Cargo.toml Cargo.toml

RUN cargo fmt --all -- --check

RUN cargo build --release --manifest-path=Cargo.toml

FROM build AS test

ENV RUST_LOG=debug

ENTRYPOINT [ "cargo"]
CMD ["test", "--release", "--manifest-path=Cargo.toml"]
