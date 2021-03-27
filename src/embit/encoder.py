from binscii import a2b_base64, b2a_base64, hexlify, unhexlify
from io import IOBase

class ENCODING:
    """Supported encodings"""
    BASE64 = 2
    BECH32 = 3
    BCUR = 4

class Reader(IOBase):
    """Enconding wrapper around a stream"""
    def __init__(self, stream):
        self.s = stream

    def read(self, *args):
        return self.s.read(*args)

    def readinto(self, *args):
        return self.s.readinto(*args)


class Writer(IOBase):
    """Enconding wrapper around a stream"""
    def __init__(self, stream):
        self.s = stream

    def write(self, *args):
        return self.s.write(*args)

    def readable(self):
        return False

    def writable(self):
        return True
