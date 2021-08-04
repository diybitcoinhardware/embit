# Overview

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
