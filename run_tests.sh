#!/bin/sh
set -e

if [ "$BUILD_SECP256K1_FROM_SOURCE" = "1" ]; then
    echo "Cloning and building secp256k1 from https://github.com/bitcoin-core/secp256k1 ..."
    git clone --branch v0.7.0 --depth 1 https://github.com/bitcoin-core/secp256k1.git /tmp/secp256k1
    cd /tmp/secp256k1
    ./autogen.sh
    ./configure --enable-module-ecdh --enable-module-recovery --enable-module-schnorrsig 
    make
    make install
    ldconfig
    cd /app
    pip install -e .
    if [ "$SEEDSIGNER" = "1" ]; then
        cd /
        apt-get update && apt-get install -y libzbar0
        git clone https://github.com/kdmukai/seedsigner.git
        cd seedsigner
        git checkout exhaustive_psbtparser_tests
        git submodule init
        git submodule update
        pip install -r requirements.txt
        pip install -e .
    else
        echo "Using system or prebuilt secp256k1."
    fi
    

else
    echo "Using system or prebuilt secp256k1."
fi

pytest -v 