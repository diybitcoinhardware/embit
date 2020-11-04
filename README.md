# embit

A minimal bitcoin library for MicroPython and Python3 with a focus on embedded systems.

Should remain minimal to fit in a microcontroller. Also easy to audit.

Examples can be found in [`examples/`](./examples) folder.

Micropython-specific tutorial [here](https://github.com/diybitcoinhardware/f469-disco/tree/master/docs/tutorial).

# Requirements

## MicroPython

Requires a custom MicroPython build with extended [`hashlib`](https://github.com/diybitcoinhardware/f469-disco/tree/master/usermods/uhashlib) module and [`secp256k1`](https://github.com/diybitcoinhardware/secp256k1-embedded) bindings.

To install copy the content of `embit` folder to the board. To save some space you can remove files `embit/util/ctypes_secp256k1.py` and `embit/util/pyhashlib.py` - they are used only in Python3.

## Python 3

Can use [libsecp256k1](https://github.com/bitcoin-core/secp256k1) with ctypes if it is installed in the system. Otherwise uses pure python implementation.

To install run `pip3 install embit`.

To install in development mode (editable) clone and run `pip3 install -e .` from the root folder.
