FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-setuptools \
        python3-wheel \
        ninja-build \
        build-essential \
        flex \
        bison \
        git \
        cmake \
        meson \
        libsctp-dev \
        libgnutls28-dev \
        libgcrypt-dev \
        libssl-dev \
        libmongoc-dev \
        libbson-dev \
        libyaml-dev \
        libmicrohttpd-dev \
        libcurl4-gnutls-dev \
        libnghttp2-dev \
        libtins-dev \
        libtalloc-dev \
        libc-ares-dev \
        iproute2 \
        iptables \
        ca-certificates \
        netbase \
        pkg-config \
        procps \
        coreutils && \
    if apt-cache show libidn-dev > /dev/null 2>&1; then \
        apt-get install -y --no-install-recommends libidn-dev; \
    else \
        apt-get install -y --no-install-recommends libidn11-dev; \
    fi && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Bind-mount the source for the build so the tree is not stored in the image.
# Requires BuildKit, which is the default in current Docker.
RUN --mount=type=bind,source=.,target=/open5gs,ro \
    cp -a /open5gs /tmp/src && \
    meson setup /tmp/src/build /tmp/src --prefix=/usr --buildtype=release && \
    ninja -C /tmp/src/build && \
    ninja -C /tmp/src/build install && \
    rm -rf /tmp/src

# Keep defaults outside /etc so a host bind mount can hide /etc without
# losing the files used to seed an empty config directory.
RUN mkdir -p /opt/open5gs \
    && cp -a /etc/open5gs /opt/open5gs/default-config \
    && cp -a /etc/freeDiameter /opt/open5gs/default-freediameter

COPY docker/runtime/open5gs-net.sh /usr/local/bin/open5gs-net.sh
COPY docker/runtime/open5gs-run.sh /usr/local/bin/open5gs-run
RUN chmod 755 /usr/local/bin/open5gs-net.sh /usr/local/bin/open5gs-run

CMD ["/usr/local/bin/open5gs-net.sh"]
