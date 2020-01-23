# embit

A minimal bitcoin library for MicroPython and Python3 with a focus on embedded systems.

Should remain minimal to fit in a microcontroller. Also easy to audit.

Examples can be found in [`examples/`](./examples) folder.

# Requirements

## MicroPython

Requires extended [`hashlib`](https://github.com/diybitcoinhardware/f469-disco/tree/master/usermods/uhashlib) module and [`secp256k1`](https://github.com/diybitcoinhardware/f469-disco/tree/master/usermods/usecp256k1) bindings.

## Python 3

Requires [libsecp256k1](https://github.com/bitcoin-core/secp256k1).