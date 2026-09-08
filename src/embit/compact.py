"""Compact Int parsing / serialization"""

import io


def to_bytes(i: int) -> bytes:
    """encodes an integer as a compact int"""
    if i < 0:
        raise ValueError("integer can't be negative: {}".format(i))
    order = 0
    while i >> (8 * (2**order)):
        order += 1
    if order == 0:
        if i < 0xFD:
            return bytes([i])
        order = 1
    if order > 3:
        raise ValueError("integer too large: {}".format(i))
    return bytes([0xFC + order]) + i.to_bytes(2**order, "little")


def from_bytes(b: bytes) -> int:
    s = io.BytesIO(b)
    res = read_from(s)
    if len(s.read(1)) > 0:
        raise ValueError("Too many bytes")
    return res


def read_from(stream) -> int:
    """reads a compact integer from a stream"""
    c = stream.read(1)
    if not isinstance(c, bytes):
        raise TypeError("Bytes must be returned from stream.read()")
    if len(c) != 1:
        raise RuntimeError("Can't read one byte from the stream")
    i = c[0]
    if i >= 0xFD:
        bytes_to_read = 2 ** (i - 0xFC)
        b = stream.read(bytes_to_read)
        if len(b) != bytes_to_read:
            raise RuntimeError("Can't read %d bytes from the stream" % bytes_to_read)
        res = int.from_bytes(b, "little")
        # reject non-canonical encodings like Bitcoin Core does: the value must
        # not fit in the next shorter encoding
        if res < (0xFD if i == 0xFD else 1 << (4 * bytes_to_read)):
            raise ValueError("Non-canonical compact int encoding")
        return res
    else:
        return i
