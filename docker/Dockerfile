# Reproducible build environment for libsecp256k1 (the C library that the embit
# ctypes backend wraps). Replaces shipped prebuilt binaries: consumers run this
# container to compile their own .so/.dll for their target.
#
# Targets supported (Linux + Windows + ARM):
#   - linux/amd64        (x86_64)
#   - linux/arm/v6       (Pi Zero -- armv6l)
#   - linux/arm/v7       (Pi 2/3 -- armv7l)
#   - linux/arm64        (aarch64)
#   - windows/amd64      (mingw cross to .dll)
#
# macOS targets are deliberately NOT supported by this image -- Apple's
# licensing makes Mach-O cross-compilation from Linux awkward, and the native
# `make` workflow on a Mac is fast enough that the isolation gain isn't worth
# the third-party toolchain dependency. See docker/README.md for the macOS
# instructions.
#
# This image is NOT invoked automatically by `pip install embit`. It is a
# deliberate manual step. See docker/README.md.
#
# syntax=docker/dockerfile:1.6

# Pinned by digest so a clean rebuild gets the same Debian image bits as the
# previous one. Bumping this is a deliberate maintainer action -- weigh the
# security updates in the new digest against any toolchain churn it pulls in.
# To bump: `docker pull debian:bookworm-slim && docker inspect --format='{{index .RepoDigests 0}}' debian:bookworm-slim`.
FROM debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716

ENV DEBIAN_FRONTEND=noninteractive

# Point apt at snapshot.debian.org so package versions are deterministic.
# Every `apt-get install <name>` against this snapshot resolves to the same
# version every time, until a maintainer bumps DEBIAN_SNAPSHOT below.
#
# This image is a transient build environment processing trusted input
# (SHA-pinned secp256k1 source); it doesn't run as a service or process
# untrusted data, so we deliberately trade automatic security-update
# pickup for fully-deterministic builds.
#
# To bump the snapshot: pick a recent date from
# https://snapshot.debian.org/archive/debian/?year=...&month=...
# (any YYYYMMDDTHHMMSSZ that resolves -- apt will follow snapshot.debian.org's
# internal redirect to the nearest actual snapshot).
ARG DEBIAN_SNAPSHOT=20260601T000000Z
RUN echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm main"          >  /etc/apt/sources.list && \
    echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ bookworm-security main" >> /etc/apt/sources.list && \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/10-snapshot && \
    echo 'Acquire::Retries "5";'              >> /etc/apt/apt.conf.d/10-snapshot

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        autoconf \
        automake \
        build-essential \
        ca-certificates \
        ccache \
        file \
        git \
        gcc-aarch64-linux-gnu \
        gcc-arm-linux-gnueabihf \
        gcc-mingw-w64-x86-64 \
        gcc-x86-64-linux-gnu \
        libc6-dev-amd64-cross \
        libc6-dev-arm64-cross \
        libc6-dev-armhf-cross \
        libtool \
        make \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Wire ccache symlinks for every cross toolchain. Debian's `ccache` package only
# auto-symlinks the native `gcc`; cross-compilers need explicit symlinks so the
# Makefile's `$(TOOLCHAIN_PREFIX)gcc` invocation routes through ccache without
# any Makefile changes. CCACHE_DIR is bind-mountable so consumers can persist
# the cache between container runs (e.g. -v $PWD/.ccache:/ccache).
RUN set -eux; \
    for triple in arm-linux-gnueabihf aarch64-linux-gnu x86_64-linux-gnu x86_64-w64-mingw32; do \
        ln -sf /usr/bin/ccache /usr/lib/ccache/${triple}-gcc; \
    done

ENV PATH="/usr/lib/ccache:${PATH}"
ENV CCACHE_DIR=/ccache

# Pre-create the ccache directory world-writable (sticky bit, like /tmp) so
# the container works correctly whether it runs as root, as the host uid via
# --user, or with a bind-mounted host directory at /ccache. Without this,
# ccache's "create /ccache/tmp" probe fails with Permission denied when the
# container runs as a non-root uid against the image's own /ccache.
RUN mkdir -p /ccache && chmod 1777 /ccache

WORKDIR /embit

COPY build.sh /usr/local/bin/build.sh
RUN chmod +x /usr/local/bin/build.sh

# Default entrypoint exposes the wrapper script. Override with `--entrypoint`
# for ad-hoc shell access.
ENTRYPOINT ["/usr/local/bin/build.sh"]
CMD ["--help"]
