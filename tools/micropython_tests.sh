#!/usr/bin/env bash
# Build the MicroPython 1.11 unix port with the hashlib and secp256k1 usermods
# embit needs, then run tests/run_tests.py on it.
# 1.11 is the oldest core embit runs on in the wild (Krux devices).
#
# The build is kept in $MP_BUILD_DIR and reused until one of the pins changes.
set -euo pipefail

MICROPYTHON_SHA=6f75c4f3cd393131579db70cdf0b35d1fe5b95ab # v1.11
F469_DISCO_SHA=989654e7bbffa255384c052fc5e4f387a2d8862a # usermods/uhashlib
SECP256K1_EMBEDDED_SHA=036f4656335fcbce978d38a7d1ea369c6d39d051
SECP256K1_SHA=be8d9c262f46309d9b4165b0498b71d704aba8fe # submodule of secp256k1-embedded

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${MP_BUILD_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/embit-micropython-1.11}"
MP="$WORK/micropython/ports/unix/micropython"
PINS="$MICROPYTHON_SHA $F469_DISCO_SHA $SECP256K1_EMBEDDED_SHA $SECP256K1_SHA"

fetch() { # <dir> <url> <sha>
    mkdir -p "$1"
    git -C "$1" init -q
    git -C "$1" fetch -q --depth 1 "$2" "$3"
    git -C "$1" -c advice.detachedHead=false checkout -q FETCH_HEAD
}

if [ ! -x "$MP" ] || [ "$(cat "$WORK/pins" 2>/dev/null)" != "$PINS" ]; then
    fetch "$WORK/micropython" https://github.com/micropython/micropython "$MICROPYTHON_SHA"
    fetch "$WORK/f469-disco" https://github.com/diybitcoinhardware/f469-disco "$F469_DISCO_SHA"
    fetch "$WORK/usermods/secp256k1" https://github.com/diybitcoinhardware/secp256k1-embedded "$SECP256K1_EMBEDDED_SHA"
    fetch "$WORK/usermods/secp256k1/secp256k1" https://github.com/bitcoin-core/secp256k1 "$SECP256K1_SHA"
    rm -rf "$WORK/usermods/uhashlib"
    cp -r "$WORK/f469-disco/usermods/uhashlib" "$WORK/usermods/uhashlib"

    make -C "$WORK/micropython/ports/unix" -j"$(getconf _NPROCESSORS_ONLN)" \
        USER_C_MODULES="$WORK/usermods" \
        CFLAGS_EXTRA='-DMODULE_HASHLIB_ENABLED=1 -DMODULE_SECP256K1_ENABLED=1 "-DMP_ROM_NONE=MP_ROM_PTR(&mp_const_none_obj)"' \
        MICROPY_PY_USSL=0 MICROPY_PY_BTREE=0 MICROPY_PY_FFI=0 MICROPY_PY_THREAD=0 MICROPY_PY_JNI=0 \
        FROZEN_MPY_DIR= CWARN="-Wall -Wno-error" COPT="-Os -Wno-error"
    echo "$PINS" > "$WORK/pins"
fi

# The 1.11 unix port only has the u-prefixed module names.
mkdir -p "$WORK/shims"
for m in binascii io collections struct json os time re random errno zlib heapq select; do
    echo "from u$m import *" > "$WORK/shims/$m.py"
done

cd "$REPO/tests"
MICROPYPATH="$WORK/shims" "$MP" -X heapsize=16M run_tests.py
