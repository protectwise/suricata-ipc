FROM ubuntu:xenial AS system-setup

WORKDIR /build

RUN apt-get update -y && apt-get install -y wget software-properties-common
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN apt-add-repository "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-8 main" \
  && apt-get update -y \
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
    hardening-wrapper \
    wget \
    build-essential
  && rm -rf /var/lib/apt || true

ENV RUST_BACKTRACE=1 \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

ARG RUST_VERSION=stable
RUN RUST_VERSION=$RUST_VERSION curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain $RUST_VERSION -y

RUN rustup component add --toolchain $RUST_VERSION rustfmt && cargo install cargo-release

FROM system-setup AS build-suricata

WORKDIR $BUILD_DIR

#Checkout suricata
ARG SURICATA_VERSION=5.0.0
RUN SURICATA_VERSION=$SURICATA_VERSION git clone https://github.com/dbcfd/suricata

WORKDIR $BUILD_DIR/suricata

RUN git pull && git checkout -b sensicata origin/sensicata

RUN git rev-parse --short HEAD

# libhtp stuffs here
RUN git clone https://github.com/ironbee/libhtp

RUN sh autogen.sh \
  && sh configure --prefix=/usr/ --sysconfdir=/etc/ --localstatedir=/var/ --enable-unix-socket --enable-pcre-jit \
  --with-libpcre-includes=/usr/local/include --with-libpcre-libraries=/usr/lib --disable-gccmarch-native \
  && make \
  && make install \
  && make install-conf \
  && rm -rf $BUILD_DIR/suricata

RUN /usr/bin/suricata -V

ENV SURICATA_EXE=/usr/bin/suricata

FROM suricata-setup AS development

ENV RUST_LOG=suricata_rs=debug \
    SURICATA_EXE=/usr/bin/suricata \
    SURICATA_CONFIG_DIR=/usr/etc/suricata \
    SURICATA_LOG_DIR=/tmp \
    SC_LOG_LEVEL=info

WORKDIR /development

VOLUME ["/development"]

ENTRYPOINT ["/bin/bash"]

FROM development AS test

ADD /benches benches
ADD /examples examples
ADD /resources resources
ADD /src src
ADD /templates templates
ADD /tests tests
ADD /Cargo.toml .

ENV RUST_VERSION=beta
RUN cargo +$RUST_VERSION fmt --all -- --check

RUN cargo build --release --manifest-path=Cargo.toml

RUN mkdir /tmp

ENTRYPOINT [ "cargo"]
CMD ["test", "--release", "--manifest-path=Cargo.toml"]
