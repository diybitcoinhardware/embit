# Overview

`embit` is a bitcoin library designed to run either with Python 3 on a PC or with [MicroPython](https://micropython.org/) on embedded devices.

For cryptography it uses [libsecp256k1](https://github.com/bitcoin-core/secp256k1) library maintained by [Bitcoin Core](https://bitcoincore.org/) team for elliptic, and everything else is implemented in python.

## Supported features:

- [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki), [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) key derivation (API docs: [bip39](./api/bip39.md), [bip32](./api/bip32.md))
- parsing and signing [PSBT](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) transactions - both version 1 and 2 ([API docs](./api/psbt.md))
- signing with custom SIGHASH flags
- Descriptors and miniscript support ([API docs](./api/descriptor.md))
- SLIP-39 Shamir Secret Sharing scheme (experimental, [API docs](./api/slip39.md))
- Liquid network support (experimental, [API docs](./api/liquid/README.md))
- Taproot support (in progress, experimental)

## Installation

**Python 3:**
```sh
pip3 install embit
```

**Micropython:** requires custom build with C bindings to hashlib and secp256k1. Docs TBD, see examples for now: [stm32](https://github.com/diybitcoinhardware/f469-disco), [RiscV](https://github.com/stepansnigirev/MaixPy), [esp32](https://github.com/stepansnigirev/esp32_embit)

<!-- For more details check out [installation instructions](./install.md). -->

## Basic usage

This script generates bip39 recovery phrase, converts it to the root key, derives native segwit xpub, prints first 5 receiving addresses, parses PSBT transaction and signs it.

We use `hexlify` and `%s` formatting to keep it compatible with MicroPython, if you use Python3 you can use `.hex()` and f-strings.

For more details check out the [API docs](./api/README.md)

```python
from embit import bip32, bip39
from embit.psbt import PSBT
from embit.descriptor import Descriptor
from binascii import hexlify

# Generate mnemonic from 16 bytes of entropy (use real entropy here!):
mnemonic = bip39.mnemonic_from_bytes(b"128 bits is fine")
# >>> couple mushroom amount shadow nuclear define like common call crew fortune slice

# Generate root privkey, password can be omitted if you don't want it
seed = bip39.mnemonic_to_seed(mnemonic, password="my bip39 password")
root = bip32.HDKey.from_seed(seed)

# Derive and convert to pubkey
xpub = root.derive("m/84h/0h/0h").to_public()

# Generate native segwit descriptors.
# You can use {0,1} for combined receive and change descriptors
desc = Descriptor.from_string("wpkh([%s/84h/0h/0h]%s/{0,1}/*)" % (hexlify(root.my_fingerprint).decode(), xpub))
# >>> wpkh([67c32a74/84h/0h/0h]xpub6CH26VtYLqm5nw8UKA2qH8doMrvGZUpeQst1JkrmyGo9LYRoKVnyfgdvjcVQoK4XSWUwyZEcupk8wBh6a2mLJ82ouUo9x2n1Y3zeoEcRSYr/{0,1}/*)

# Print first 5 addresses
for i in range(5):
    print(desc.derive(i).address())

# parse base64-encoded PSBT transaction
psbt = PSBT.from_string("cHNidP8BAHECAAAAAaW9Cd1X07XEcA/D0XmE5dwI2AEQr4aTTTwBqopD1mxAAAAAAAD9////AvJJXQUAAAAAFgAUUa2Cs4u5XOmDFhwNxl/szK5L9beAlpgAAAAAABYAFCwSoUTerJLG437IpfbWF8DgWx6kAAAAAAABAHECAAAAATVenbXof59P6l5N+BxpXQytbyWp29JfJDyT+OwohRWKAAAAAAD+////AgDh9QUAAAAAFgAUgmkBPePxvl4jTWsuNNnypKngm824IKMwAAAAABYAFOiPQIZGLU3UZ8JugMpHcCwxmUK2zQEAAAEBHwDh9QUAAAAAFgAUgmkBPePxvl4jTWsuNNnypKngm80iBgPHS/KrcrFXnxQ0/kvZeBkmEsQGjBLEc5JRUjzP9yVXVhhnwyp0VAAAgAAAAIAAAACAAAAAAAAAAAAAIgIC9jzRiRyPDoZ5F2xMV/QfW6qma/6i0PtyELYn8YR5PjsYZ8MqdFQAAIAAAACAAAAAgAEAAAAAAAAAAAA=")

# only print outputs that are not change
for out in psbt.outputs:
    if not desc.owns(out):
        print("Send %d to %s" % (out.value, out.script_pubkey.address()))
# print fee
print("fee: %d" % psbt.fee())

# sign psbt and print it
psbt.sign_with(root)
print(psbt)

```

## Projects using embit

### Hardware wallets

- [Specter-DIY](https://github.com/cryptoadvance/specter-diy) - airgapped hardware wallet on STM32F469NI-Discovery board (STM32)
- [SeedSigner](https://github.com/SeedSigner/seedsigner) - airgapped hardware wallet on Raspberry Pi Zero
- [krux](https://github.com/jreesun/krux) - airgapped hardware wallet on M5StickV developer board (RiscV)

### Software wallets

- [Specter-Desktop](https://github.com/cryptoadvance/specter-desktop)
- [LNBits](https://github.com/lnbits/lnbits/tree/master/lnbits/extensions/watchonly) watch only extension
