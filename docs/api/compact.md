# Compact (varint)

Compact encoding is often used in Bitcoin serializations (i.e. `Script` length serializations).

**Example**

```python
from embit import compact

compact.to_bytes(255)
# b'\xfd\xff\x00'
compact.to_bytes(21)
# b'\x15'

compact.from_bytes(b'\xfd\xff\x00')
# 255

# read from stream:
with open("somefile", "rb") as f:
	compact.read_from(f)

```

## `to_bytes(i)`

Encodes an integer as compact int (varint).

Integers smaller than `253` are encoded in `1` byte, larger integers are encoded as prefix defining how many bytes will follow and `2`, `4` or `8` bytes of the integer itself.


**Arguments**

- `i`: integer to convert to bytes

**Returns**

Bytearray with encoded integer. The result will be `1`, `3`, `5` or `9` bytes long.


## `from_bytes(b)`

Decodes an integer from bytes.

**Arguments**

- `b`: bytes with a correctly encoded compact int, `1`, `5`, `7` or `9` bytes long.

**Returns**

Decoded integer.

Raises en exception if decoding failed.

## `read_from(stream)`

Reads a compact integer from a stream.

**Arguments**

-`stream` - a readable object (`BytesIO`, file open for binary reading etc)

**Returns**

An integer read from the stream.
