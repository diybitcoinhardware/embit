# `PublicKey`

Individual public key class.

## Constructor

```python
PublicKey(point, compressed=True)`
```

> This constructor is not very useful, probably better to instatiate this class by parsing serialized public key or creating it from private key.

- `point` - `64`-bytes internal representation of a point used by `libsecp256k1`.
- `compressed = True` - whether to use compressed or uncompressed public keys. For any modern applications always use compressed keys (default).

## Serialization

`33`-byte or `65`-byte SEC serialization, depending on the `compressed` property.

For `pub.compressed = True` serialized as `33` bytes, first byte is `02` or `03` depending on the sign of the point, followed by the `x`-coordinate of the point.

For `pub.compressed = False` serialized as `65` bytes, first byte is `04`, followed by the `x`-coordinate of the point and the `y`-coordinate.

**Parsing (class methods):**

- `PublicKey.parse(bytes)` - parses a SEC-encoded public key from bytes.
- `PublicKey.read_from(stream)` - reads SEC-encoded public key from stream. It will read either `33` or `65` bytes depending on the first byte of the serialization.

**Serialization:**

- `pub.sec()` - returns SEC-serialized pubkey - `33` or `65` bytes depending on the `compressed` flag.
- `pub.serialize()` - same as `pub.sec()`
- `pub.write_to(stream)` - writes SEC-serialized pubkey to stream.

**Taproot related:**

!> Schnorr and taproot support is experimental and API is not stable yet!

- `PublicKey.from_xonly(bytes)` - lifts x coordinate of the point to xonly pubkey. Effectively the same as parsing `0x02<x>`.
- `pub.xonly()` - returns a `32`-byte x-only representation of the pubkey (x coordinate of the point). Same as `pub.sec()[1:33]`.

## String representation

Public key doesn't have a human-readable representation, so we use hex-encoded SEC serialization.

- `PublicKey.from_string("0254a4b...3943")` - converts a string from hex to bytes and parses public key from it.
- `pub.to_string()` or `str(pub)` - hex of SEC

## Attributes

You can change them at any time.

- `compressed` - compressed flag, `bool`

!> Avoid uncompressed keys if possible. Beware that uncompressed pubkeys will lead to different scripts comparing to compressed, and these scripts could be invalid (i.e. `script.p2wpkh(pub)`).

**Example**

```python
from embit import ec

pk = ec.PrivateKey(b"1"*32)
pub = pk.get_public_key()

# compressed is True by default
print(pub)
# >>> 036930f46d...1cafceb82

pub.compressed = False
# now it will be printed or serialized as uncompressed
print(pub)
# >>> 046930f46dd0b16d866d59d1...33c3d37fe6ab
```

## Properties

These properties only implement getter, so you can't change them.

- `is_private` - `bool`, always returns `False`. Useful in things like `Descriptor` or `HDKey` where internal key can be either private or public.

## Methods

- [`sec()`](#sec) - SEC serialization.
- [`xonly()`](#xonly) - x-only serialization.
- [`verify(sig, msg)`](#verify) - verifies ECDSA signature for the message.
- [`schnorr_verify(schnorrsig, msg)`](#schnorr_verify) - verifies schnorr signature for the message.
- [`taproot_tweak()`](#taproot_tweak)

### `sec()`

Serializes the public key in SEC format.

For `pub.compressed = True` serialized as `33` bytes, first byte is `02` or `03` depending on the sign of the point, followed by the `x`-coordinate of the point.

For `pub.compressed = False` serialized as `65` bytes, first byte is `04`, followed by the `x`-coordinate of the point and the `y`-coordinate.

**Returns**

Bytes, `33` or `65` depending on the `compressed` attribute.

### `xonly()`

Serializes the public key as x-only (`taproot`).

**Returns**

`32`-bytes with `x`-coordinate of the public key.

### `verify()`

Verifies ECDSA signature against the message.

**Arguments**

- `sig` - Instance of ECDSA [`Signature`](./signature.md) to verify
- `msg` - `32`-byte hash of the message to verify against.

**Returns**

`True` if the signature is valid, `False` otherwise.

### `schnorr_verify()`

Verifies Schnorr signature against the message.

**Arguments**

- `sig` - Instance of [`SchnorrSig`](./shcnorr_sig.md) to verify
- `msg` - `32`-byte hash of the message to verify against.

**Returns**

`True` if the signature is valid, `False` otherwise.

### `taproot_tweak()`

!> Schnorr and taproot support is experimental and API is not stable yet!

Tweaks the public key with taproot script hash according to [BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs).

**Arguments**

- `tweak = b""` - a `32`-byte hash of the taproot scripts. Default: `b""` - it's a default tweak with empty script tree.

**Returns**

A tweaked instance of `PublicKey`.
