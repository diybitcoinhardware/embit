"""Base classes"""
from io import BytesIO
from binascii import hexlify, unhexlify


class EmbitError(Exception):
    """Generic Embit error"""

    pass


class EmbitBase:
    @classmethod
    def read_from(cls, stream, *args, **kwargs):
        """All classes should be readable from stream"""
        raise NotImplementedError(
            "%s doesn't implement reading from stream" % cls.__name__
        )

    @classmethod
    def parse(cls, s: bytes, *args, **kwargs):
        """Parse raw bytes"""
        stream = BytesIO(s)
        res = cls.read_from(stream, *args, **kwargs)
        if len(stream.read(1)) > 0:
            raise EmbitError("Unexpected extra bytes")
        return res

    def write_to(self, stream, *args, **kwargs) -> int:
        """All classes should be writable to stream"""
        raise NotImplementedError(
            "%s doesn't implement writing to stream" % type(self).__name__
        )

    def serialize(self, *args, **kwargs) -> bytes:
        """Serialize instance to raw bytes"""
        stream = BytesIO()
        self.write_to(stream, *args, **kwargs)
        return stream.getvalue()

    def to_string(self, *args, **kwargs) -> str:
        """
        String representation.
        If not implemented - uses hex or calls to_base58() method if defined.
        """
        if hasattr(self, "to_base58"):
            res = self.to_base58(*args, **kwargs)
            if not isinstance(res, str):
                raise ValueError("to_base58() must return string")
            return res
        return hexlify(self.serialize(*args, **kwargs)).decode()

    @classmethod
    def from_string(cls, s, *args, **kwargs):
        """Create class instance from string"""
        if hasattr(cls, "from_base58"):
            return cls.from_base58(s, *args, **kwargs)
        return cls.parse(unhexlify(s))

    def __str__(self):
        """Internally calls `to_string()` method with no arguments"""
        return self.to_string()

    def __repr__(self):
        try:
            return type(self).__name__ + "(%s)" % str(self)
        except:
            return type(self).__name__ + "()"

    def __eq__(self, other):
        """Compare two objects by checking their serializations"""
        if not hasattr(other, "serialize"):
            return False
        return self.serialize() == other.serialize()

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.serialize())


class EmbitKey(EmbitBase):
    def sec(self) -> bytes:
        """
        Any EmbitKey should implement sec() method that returns
        a sec-serialized public key
        """
        raise NotImplementedError(
            "%s doesn't implement sec() method" % type(self).__name__
        )

    def xonly(self) -> bytes:
        """xonly representation of the key"""
        return self.sec()[1:33]

    @property
    def is_private(self) -> bool:
        """
        Any EmbitKey should implement `is_private` property to distinguish
        between private and public keys.
        """
        raise NotImplementedError(
            "%s doesn't implement is_private property" % type(self).__name__
        )

    def __lt__(self, other):
        # for lexagraphic ordering
        return self.sec() < other.sec()

    def __gt__(self, other):
        # for lexagraphic ordering
        return self.sec() > other.sec()

    def __hash__(self):
        return hash(self.serialize())
