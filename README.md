# embit

A minimal bitcoin library for MicroPython and Python3 with a focus on embedded systems.

Should remain minimal to fit in a microcontroller. Also easy to audit.

Examples can be found in [`examples/`](./examples) folder.

Micropython-specific tutorial [here](https://github.com/diybitcoinhardware/f469-disco/tree/master/docs/tutorial).

# Requirements

## MicroPython

Requires a custom MicroPython build with extended [`hashlib`](https://github.com/diybitcoinhardware/f469-disco/tree/master/usermods/uhashlib) module and [`secp256k1`](https://github.com/diybitcoinhardware/f469-disco/tree/master/usermods/usecp256k1) bindings.

To install copy the content of `embit` folder to the board. To save some space you can remove files `embit/util/ctypes_secp256k1.py` and `embit/util/pyhashlib.py` - they are used only in Python3.

## Python 3

Requires [libsecp256k1](https://github.com/bitcoin-core/secp256k1).

To install run `pip3 install .`.

To install in development mode (editable) run `pip3 install -e .`