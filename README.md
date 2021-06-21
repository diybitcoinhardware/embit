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


## Using non-English BIP39 wordlists
[BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md) defines wordlists for:
* English
* Japanese
* Korean
* Spanish
* Chinese (Simplified)
* Chinese (Traditional)
* French
* Italian
* Czech
* Portuguese

`embit` assumes English and does not include the other wordlists in order to keep this as slim as possible.

However, you can override this default by providing an alternate wordlist to any of the mnemonic-handling methods:
```
spanish_wordlist = [
    "ábaco",
    "abdomen",
    "abeja",
    "abierto",
    "abogado",
    "abono",
    "aborto",
    "abrazo",
    "abrir",
    "abuelo",
    ...
]

mnemonic_is_valid(mnemonic, wordlist=spanish_wordlist)
mnemonic_to_seed(mnemonic, wordlist=spanish_wordlist)
mnemonic_to_bytes(mnemonic, wordlist=spanish_wordlist)
mnemonic_from_bytes(bytes_data, wordlist=spanish_wordlist)
```
