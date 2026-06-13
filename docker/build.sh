#!/usr/bin/env bash
# Convenience wrapper around secp256k1/Makefile that selects the right
# toolchain triple and CFLAGS for a named target.
#
# Source is fixed to secp256k1-zkp (the Blockstream fork) because Liquid
# support requires its extra crypto modules (ECDH, generator, pedersen,
# rangeproof, surjectionproof, musig, schnorrsig). This can be swapped to
# upstream bitcoin-core/secp256k1 in the future, once Liquid lives in a
# separate external module that owns its own zkp build.
#
# Output lands at:
#   secp256k1/build/libsecp256k1_<platform>_<arch>.{so,dll}
# (the Makefile decides the filename based on PLATFORM and ARCH it sees.)
#
# Run inside the docker image:
#   docker run --rm -v "$PWD":/embit -v "$PWD/.ccache":/ccache embit-libsecp <target>
#
# Targets:
#   amd64        Native Linux x86_64 build
#   armv6l       Cross-compile for Raspberry Pi Zero
#   armv7l       Cross-compile for Raspberry Pi 2/3 / armhf
#   aarch64      Cross-compile for arm64 (Pi 4/5, modern ARM Linux)
#   windows      Cross-compile to .dll via mingw-w64
#   all          Build every target above in sequence. Individual failures
#                do not abort the run; the script exits non-zero at the end
#                if any target failed, so a single invocation surfaces every
#                broken target at once.
#   --help       Show this message
#
# macOS targets are not supported by this container -- build natively on a
# Mac with the existing secp256k1/Makefile. See docker/README.md.

set -euo pipefail

SECP_DIR="/embit/secp256k1"

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
}

if [ "$#" -lt 1 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    usage
    exit 0
fi

TARGET="$1"
shift || true

# `all` recurses into the script for each supported target. Any extra args
# the caller passed in are forwarded to every per-target invocation. We
# continue past individual failures so a single run shows every broken
# target, then exit non-zero at the end if anything failed.
if [ "${TARGET}" = "all" ]; then
    rc=0
    for t in amd64 armv6l armv7l aarch64 windows; do
        echo ""
        echo "===== build.sh: ${t} ====="
        "$0" "${t}" "$@" || rc=$?
    done
    exit "${rc}"
fi

if [ ! -d "${SECP_DIR}" ]; then
    echo "ERROR: ${SECP_DIR} not found. Mount the embit repo at /embit:" >&2
    echo "  docker run --rm -v \"\$PWD\":/embit ... <target>" >&2
    exit 1
fi

if [ ! -d "${SECP_DIR}/secp256k1-zkp" ] || [ -z "$(ls -A "${SECP_DIR}/secp256k1-zkp" 2>/dev/null || true)" ]; then
    echo "ERROR: secp256k1-zkp submodule is not checked out." >&2
    echo "  git submodule update --init --recursive" >&2
    exit 1
fi

case "${TARGET}" in
    amd64|x86_64|linux-amd64)
        # Explicit cross-compiler so the produced binary is x86_64 regardless
        # of the container's host architecture. Without this, the build would
        # silently produce an arm64 binary when run on Apple Silicon (Docker
        # Desktop's default linux/arm64 image variant).
        MAKE_ARGS=(
            PLATFORM=linux
            ARCH=x86_64
            "TOOLCHAIN_PREFIX=x86_64-linux-gnu-"
        )
        BUILT_NAME=libsecp256k1_linux_x86_64.so
        ;;
    armv6l|pi-zero|linux-armv6l)
        # -marm forces ARM (not Thumb) instruction selection; ARMv6 Thumb-1
        # does not support hard-float VFP, so without -marm gcc errors out
        # with "sorry, unimplemented: Thumb-1 'hard-float' VFP ABI". This
        # matches Raspbian's stock toolchain for Pi Zero hard-float builds.
        MAKE_ARGS=(
            PLATFORM=linux
            ARCH=armv6l
            "TOOLCHAIN_PREFIX=arm-linux-gnueabihf-"
            "CFLAGS=-fPIC -O2 -Werror -Wno-unused-function -march=armv6 -mfpu=vfp -mfloat-abi=hard -marm -I${SECP_DIR}/secp256k1-zkp -I${SECP_DIR}/secp256k1-zkp/src -I${SECP_DIR}/config -DHAVE_CONFIG_H"
        )
        BUILT_NAME=libsecp256k1_linux_armv6l.so
        ;;
    armv7l|pi-2|linux-armv7l)
        MAKE_ARGS=(
            PLATFORM=linux
            ARCH=armv7l
            "TOOLCHAIN_PREFIX=arm-linux-gnueabihf-"
            "CFLAGS=-fPIC -O2 -Werror -Wno-unused-function -march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=hard -I${SECP_DIR}/secp256k1-zkp -I${SECP_DIR}/secp256k1-zkp/src -I${SECP_DIR}/config -DHAVE_CONFIG_H"
        )
        BUILT_NAME=libsecp256k1_linux_armv7l.so
        ;;
    aarch64|arm64|linux-aarch64)
        MAKE_ARGS=(
            PLATFORM=linux
            ARCH=aarch64
            "TOOLCHAIN_PREFIX=aarch64-linux-gnu-"
        )
        BUILT_NAME=libsecp256k1_linux_aarch64.so
        ;;
    windows|win|win64|windows-amd64)
        MAKE_ARGS=(CROSS_DLL=1)
        BUILT_NAME=libsecp256k1_windows_amd64.dll
        ;;
    darwin-*|macos-*)
        echo "ERROR: macOS targets are not built inside this container." >&2
        echo "       Build natively on a Mac: 'cd secp256k1 && make'." >&2
        echo "       See docker/README.md for details." >&2
        exit 1
        ;;
    *)
        echo "ERROR: unknown target '${TARGET}'" >&2
        usage >&2
        exit 1
        ;;
esac

cd "${SECP_DIR}"

# Remove stale intermediate objects from any previous build that may have
# targeted a different architecture (e.g. an earlier native macOS `make`
# run leaving a Mach-O secp256k1.o behind). Per-target .so/.dll outputs
# in build/ are preserved so consecutive cross-compile invocations don't
# clobber each other.
rm -f build/*.o build/*.d

make "${MAKE_ARGS[@]}" "$@"

# Stage only the artifact produced by THIS invocation at the autotools-
# conventional path the embit ctypes loader checks first
# (secp256k1/secp256k1-zkp/.libs/). Staging exactly the current target's
# output -- rather than globbing every libsecp256k1_*.so/.dll in build/ --
# keeps prior runs' outputs from racing for the staged slot (last-glob-win
# is shell-alphabetical, not what the caller asked for) and ensures the
# staged file matches what the caller actually requested.
LIBS_DIR="${SECP_DIR}/secp256k1-zkp/.libs"
mkdir -p "${LIBS_DIR}"

case "${BUILT_NAME}" in
    *.so)  STAGED_NAME=libsecp256k1.so ;;
    *.dll) STAGED_NAME=libsecp256k1.dll ;;
    *)
        echo "ERROR: unexpected BUILT_NAME '${BUILT_NAME}' (no .so/.dll extension)" >&2
        exit 1
        ;;
esac

if [ ! -f "${SECP_DIR}/build/${BUILT_NAME}" ]; then
    echo "ERROR: expected build/${BUILT_NAME} not found after make. Did the build silently fail?" >&2
    exit 1
fi

cp "${SECP_DIR}/build/${BUILT_NAME}" "${LIBS_DIR}/${STAGED_NAME}"
echo "Staged: ${SECP_DIR}/build/${BUILT_NAME} -> ${LIBS_DIR}/${STAGED_NAME}"

# Surface a brief summary of what was built and where.
echo ""
echo "Built artifacts:"
find "${SECP_DIR}/build" -maxdepth 1 -type f \( -name '*.so' -o -name '*.dll' \) -print

if command -v ccache >/dev/null 2>&1; then
    echo ""
    echo "ccache stats:"
    ccache -s | sed 's/^/  /'
fi
