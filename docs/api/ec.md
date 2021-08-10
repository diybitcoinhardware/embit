# Ellictic curve keys and signatures

This module includes classes for signatures and individual private and public keys.

## `PrivateKey`

Individual private key class.

**Constructor arguments**

- `secret` - `32`-byte secret
- `compressed = True` - whether to use compressed or uncompressed public keys. For any modern applications always use compressed keys (default).
- `network = NETWORKS['main']` - what network to use when converting to WIF string. Mainnet by default. See [networks](./networks.md) for more.

## `PublicKey`

## `Signature`

ECDSA signature class, can't do much - only usual serializations and parsing. `DER` representation is expected for the signature.

Signature serialization does not include `SIGHASH` flag.

## `SchnorrSig`

!> Schnorr and taproot support is experimental and API is not stable yet!
