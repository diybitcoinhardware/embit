# Base58 encoding

Common encoding format in Bitcoin - used in legacy or nested segwit addresses, WIF private keys, xpubs etc.

Normally a checksum is appended to the bytes before encoding - use `encode_check` and `decode_check` functions for that.

**Example**

```python
from embit import base58

# decode without removing checksum
base58.decode("1CxLJtbFfD7TaY47cVjSooDSQZ72eM1qDq")
# >>> b'\x00\x83 a\x1f\xf02"<\x1fK\xb1\xfb\xbd"\x91\xfd+?C\xd9]O\xbeH'

# decode, check checksum and remove it
base58.decode_check("1CxLJtbFfD7TaY47cVjSooDSQZ72eM1qDq")
# >>> b'\x00\x83 a\x1f\xf02"<\x1fK\xb1\xfb\xbd"\x91\xfd+?C\xd9

# encode without adding checksum
base58.encode(b"\x00\x00\x00\x12\x34\x56")
# >>> '11177em'

# encode and add checksum
base58.encode_check(b"\x00\x00\x00\x12\x34\x56")
'111h1iJauMk5'
```

## `encode(b)`

Encodes bytes to base58 string.

**Arguments**

- `b` - bytes to encode

**Returns**

base58-encoded string

## `decode(s)`

Decodes a string from base58 encoding

**Arguments**

- `s` - string to decode

**Returns**

Bytes decoded from string, raises an exception if decoding failed (i.e. non-alphabet characters)

## `encode_check(b)`

Encodes bytes to base58 string and appends a checksum to it.

**Arguments**

- `b` - bytes to encode

**Returns**

base58-encoded string with a checksum

## `decode_check(s)`

Decodes a string from base58, checks the checksum and removes it from the result.

**Arguments**

- `s` - string to decode

**Returns**

Bytes decoded from string without a checksum, raises an exception if decoding failed (i.e. non-alphabet characters or checksum is wrong)
