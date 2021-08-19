# `PrivateKey`

Individual private key class.

## Constructor

```python
PrivateKey(secret, compressed=True, network=NETWORKS['main'])`
```

- `secret` - `32`-byte big-endian scalar.
- `compressed = True` - whether to use compressed or uncompressed public keys. For any modern applications always use compressed keys (default).
- `network = NETWORKS['main']` - what network to use when converting to WIF string. Mainnet by default. See [networks](../networks.md) for more.

## Serialization

`32`-byte big-endian scalar.

**Parsing (class methods):**

- `PrivateKey.parse(bytes)` - parses a `32`-byte array as a big-endian scalar.
- `PrivateKey.read_from(stream)` - reads `32` bytes from stream and parses them as big-endian scalar.

**Serialization:**

- `pk.serialize()` - returns `32` bytes with secret.
- `pk.write_to(stream)` - writes `32` bytes with the secret to stream.

## String representation

[WIF](https://en.bitcoin.it/wiki/Wallet_import_format) format (wallet import format) - see [`wif`](#wif) and [`from_wif`](#from_wif) methods.

Can receive desired [network](../networks.md) as an optional argument (i.e. `pk.to_string(NETWORKS['test'])`)

- `PrivateKey.from_wif(wif)` - decodes private key from WIF string
- `PrivateKey.from_string(wif)` - same as `from_wif()`


- `pk.wif(network=None)` - encodes private key to WIF string. Optional argument is one of the `NETWORKS` to use for conversion.
- `pk.to_string(network=None)` - same as `pk.wif(network)`
- `str(pk)` - same as `pk.wif()` using default network.

## Attributes

You can change them at any time.

- `network` - [network dict](../networks.md) used for serialization.
- `compressed` - compressed flag, `bool`

**Example**

```python
from embit import ec
from embit.networks import NETWORKS

pk = ec.PrivateKey.from_string("KxsLKrFM2X4kK4zkxGtmTaWv2tvyNLdZmuMWhni3DeKDcDFeS3DU")

pk.compressed = False
pk.network = NETWORKS['test']
print(pk)
# >>> 91xaiBUgkdecTArApWPQXLVKGtUxHidJs4HXzpchGMPFhMCmEqc
```

## Properties

These properties only implement getter, so you can't change them.

- `secret` - `32`-byte big-endian scalar.
- `is_private` - `bool`, always returns `True`. Useful in things like `Descriptor` or `HDKey` where internal key can be either private or public.

## Methods

Methods of `PrivateKey`:

- [`wif()`](#wif) - returns base58-encoded private key.
- [`from_wif(s)`](#from_wif) - class method, parses a base58-encoded string and returns corresponding `PrivateKey`. 
- [`get_public_key()`](#get_public_key) - returns a `PublicKey` corresponding to private key.
- [`sign(msg)`](#sign) - signs a 32-byte message hash and returns ECDSA `Signature`.
- [`schnorr_sign(msg)`](#schnorr_sign) - signs a 32-byte message hash and returns `SchnorrSig`.
- [`taproot_tweak(tweak=b"")`](#taproot_tweak) - returns tweaked `PrivateKey` according to taproot rules.

Aliases from [`PublicKey`](./public_key.md) class - same as calling these methods on the key returned by [`pk.get_public_key()`](#get_public_key):

- [`sec()`](./public_key.md#sec) - SEC serialization of the public key.
- [`xonly()`](./public_key.md#xonly) - x-only serialization of the public key (for taproot).
- [`verify(sig, msg)`](./public_key.md#verify) - verifies ECDSA signature for the message.
- [`schnorr_verify(schnorrsig, msg)`](./public_key.md#schnorr_verify) - verifies schnorr signature for the message.

### `wif()`

[WIF](https://en.bitcoin.it/wiki/Wallet_import_format) (wallet import format) is a default human-readable format for individual private keys.

It is a base58-encoded private key with network-dependent prefix and compressed flag.

**Arguments**

- `network = None` - network dict to use for encoding. Default - internal `self.network` property.

**Returns**

WIF string

**Example**

```python
from embit.ec import PrivateKey
from embit.networks import NETWORKS

pk = PrivateKey(b"1"*32)
pk.wif()
# >>> KxsLKrFM2X4kK4zkxGtmTaWv2tvyNLdZmuMWhni3DeKDcDFeS3DU
pk.wif(NETWORKS['test'])
# >> cPEKnmFCTam1UWU2Lghtpu1yf8EP2njFqwVypDAYikyDrxLXSx4Z
```

### `from_wif()`

Class method. Parses a [WIF](https://en.bitcoin.it/wiki/Wallet_import_format) string and returns an instance of the `PrivateKey`.

**Arguments**

- `s` - WIF string to parse

**Returns**

`PrivateKey` instance.

**Example**

```python
from embit.ec import PrivateKey

pk = PrivateKey.from_wif("KxsLKrFM2X4kK4zkxGtmTaWv2tvyNLdZmuMWhni3DeKDcDFeS3DU")
```

### `get_public_key()`

**Returns**

An instance of [`PublicKey`](./public_key) class corresponding to this private key.

### `sign()`

Creates ECDSA signature for the message hash. Signatures returned by this function are created deterministically and the results are the same as if you'd sign with Bitcoin Core.

**Arguments**

- `msg` - `32`-byte message hash to sign.
- `grind = True` - whether to grind for low R value or not. With `grind = True` signature is guaranteed to be at most `70` bytes. This is done by grinding nonces for signature generation, success rate is `50%` per attempt. 

**Returns**

An instance of the [`Signature`](./signature.md) class with ECDSA signature of the message.

### `schnorr_sign()`

!> Schnorr and taproot support is experimental and API is not stable yet!

Creates a Schnorr signature for the message hash.

**Arguments**

- `msg` - `32`-byte message hash to sign.

**Returns**

An instance of the [`SchnorrSig`](./schnorr_sig.md) class with the Schnorr signature of the message as defined in [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).

### `taproot_tweak()`

!> Schnorr and taproot support is experimental and API is not stable yet!

Tweaks the private key with taproot script hash according to [BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs).

**Arguments**

- `tweak = b""` - a `32`-byte hash of the taproot scripts. Default: `b""` - it's a default tweak with empty script tree.

**Returns**

A tweaked instance of `PrivateKey`.

