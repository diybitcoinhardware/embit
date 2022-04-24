# Overview

## Basics

Almost all classes have `.parse(bytes)` and `.serialize()` functions to create class instances from bytearray and other way around. They can also read from / write to streams like files or `ByteIO` objects using `read_from(stream)` and `write_to(stream)` methods.

The only exception is `Descriptor` that is purely string-based and doesn't have any binary representation.

For example:

```python
# parsing pubkey from bytes
from embit.ec import PublicKey
from binascii import unhexlify
pub = PublicKey.parse(b"\x02\x01\x8a\x76\x85\x41\xc9\x46...\x85")

# reading raw transaction from file
from embit.transaction import Transaction
with open("raw.tx", "rb") as f:
	tx = Transaction.read_from(f)

# serialize to bytes
sec = pub.serialize()
# write to binary file
with open("raw2.tx", "wb") as f:
	tx.write_to(f)
```

Some classes also have string representations. If they don't - we assume hex representation. You can use `.from_string()` and `.to_string()` methods for that, or just call `str(something)`:

```python
from embit.bip32 import HDKey
from embit.ec import PublicKey, PrivateKey

xpub = HDKey.from_string("xpub6BysnKqL9EKxKwWxrgwU97FBNybxNZKKfGQgqurJy3BYGSJZBk4biPTzJCCMZ5wsqfxskrrUiJYQexJFX7qkA4DYB2DiADY7Fcto4wxLva4")
prv = PrivateKey.from_string("L16MDExY5qQ6ABZCvRRD3v3rXV4R3y2THZu56eFLLnGjhbqX7Gq7")
# hex representation:
pub = PublicKey.from_string("02018a768541c946e907bd6961f403edd820e76cddb40cefb3c5cf3ae47cea6186")
```


## Modules

Library is splitted into modules, list of modules sorted by topic:

**Keys:**

- [ec](./ec.md) - individual elliptic curve keys (`PrivateKey`, `PublicKey`) and signatures (`Signature`, `SchnorrSig`)
- [bip39](./bip39.md) - helper functions for mnemonics
- [bip32](./bip32.md) - extended private and public keys (`HDKey`)

**Scripts:**

- [script](./script.md) - basic bitcoin scripts (`Script`) and helper functions
- [descriptor](./descriptor/README.md) - descriptors (`Descriptor`) and miniscript functions

**Transactions:**

- [transaction](./transaction.md) - raw transactions (`Transaction`)
- [psbt](./psbt.md) - psbt transactions (`PSBT`)
- [psbtview](./psbtview.md) - RAM-optimized pbst transaction for embedded devices, doesn't read the whole transaction to memory but only gets the part you need right now (`PSBTView`)

**Helpers:**

- [networks](./networks.md) - constants for different Bitcoin networks
- [base58](./base58.md) encoding - used for WIFs and legacy addresses
- [bech32](./bech32.md) encoding - used for segwit and taproot addresses
- [compact](./compact.md) - often used for serializations
- [hashes](./hashes.md) - common bitcoin hash functions like `tagged_hash`, `double_sha256` etc

**Extensions / experimental:**
- [liquid](./liquid/README.md) - support for confidential assets, liquid transactions, blinded descriptors and psets (elements version of psbt)
- [slip39](./slip39.md) - shamir secret sharing scheme
