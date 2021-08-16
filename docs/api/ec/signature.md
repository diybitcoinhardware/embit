# `Signature`

ECDSA signature class, can't do much - only usual serializations and parsing.

!> Signature serialization does not include `SIGHASH` flag.

**Example**

```python
from embit import ec
import hashlib

pk = ec.PrivateKey(b"1"*32)
msg = hashlib.sha256(b"hello world").digest()
sig = pk.sign(msg)
print(sig)
# >>> 30440220084...f5efaf868b57246295c

pub = pk.get_public_key()
pub.verify(sig, msg)
# >>> True
```

## Constructor

```python
Signature(sig)`
```

> This constructor is not very useful, probably better to instatiate this class by parsing serialized signature or creating it using private key `.sign()` method.

- `sig` - `64`-bytes internal representation of a ECDSA signature used by `libsecp256k1`.

## Serialization

`DER` representation is used as default serialization for the signature.

**Parsing (class methods):**

- `Signature.parse(bytes)` - parses a DER-encoded ECDSA signature from bytes.
- `Signature.read_from(stream)` - reads DER-encoded signature from stream.

**Serialization:**

- `sig.serialize()` - returns bytes with DER-encoded signature.
- `sig.write_to(stream)` - writes DER-encoded signature to stream.

## String representation

Signature doesn't have a human-readable representation, so we use hex-encoded DER serialization.

- `Signature.from_string("30440220...3943")` - converts a string from hex to bytes and parses ECDSA signature from it.
- `sig.to_string()` or `str(sig)` - hex of DER encoded signature.

## Methods

This class doesn't have any methods apart from usual:

`parse(bytes)`, `serialize()`, `write_to(stream)`, `read_from(stream)`, `to_string()` and `from_string(s)`
