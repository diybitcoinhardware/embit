# `SchnorrSig`

Schnorr signature class, can't do much - only usual serializations and parsing.

!> Schnorr and taproot support is experimental and API is not stable yet!

!> `SchnorrSig` serialization does not include `SIGHASH` flag.

**Example**

```python
from embit import ec
import hashlib

pk = ec.PrivateKey(b"1"*32)
msg = hashlib.sha256(b"hello world").digest()
sig = pk.schnorr_sign(msg)
print(sig)
# >>> dbbc1549...64e480c627dd

pub = pk.get_public_key()
pub.schnorr_verify(sig, msg)
# >>> True
```

## Constructor

```python
SchnorrSig(sig)`
```

> This constructor is not very useful, probably better to instatiate this class by parsing serialized signature or creating it using private key `.schnorr_sign()` method.

- `sig` - `64`-bytes internal representation of a Schnorr signature used by `libsecp256k1`.

## Serialization

Bytes representation as defined in [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) is used as default serialization for the Schnorr signature.

**Parsing (class methods):**

- `SchnorrSig.parse(bytes)` - parses an encoded Schnorr signature from bytes.
- `SchnorrSig.read_from(stream)` - reads an encoded signature from stream.

**Serialization:**

- `sig.serialize()` - returns bytes with encoded signature.
- `sig.write_to(stream)` - writes signature to stream.

## String representation

`SchnorrSig` doesn't have a human-readable representation, so we use hex-encoded serialization.

- `SchnorrSig.from_string("30440220...3943")` - converts a string from hex to bytes and parses Schnorr signature from it.
- `sig.to_string()` or `str(sig)` - hex of the encoded signature.

## Methods

This class doesn't have any methods apart from usual:

`parse(bytes)`, `serialize()`, `write_to(stream)`, `read_from(stream)`, `to_string()` and `from_string(s)`
