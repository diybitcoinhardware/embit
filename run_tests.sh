#!/bin/sh
set -e

if [ "$BUILD_SECP256K1_FROM_SOURCE" = "1" ]; then
    echo "Cloning and building secp256k1 from https://github.com/bitcoin-core/secp256k1 ..."
    git clone --branch v0.6.0 --depth 1 https://github.com/bitcoin-core/secp256k1.git /tmp/secp256k1
    cd /tmp/secp256k1
    ./autogen.sh
    ./configure --enable-module-ecdh --enable-module-recovery --enable-module-schnorrsig 
    make
    make install
    ldconfig
    cd /app
else
    echo "Using system or prebuilt secp256k1."
fi

pytest -v 