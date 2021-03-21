"""Base classes"""
from io import BytesIO

class EmbitError(Exception):
    """Generic Embit error"""
    pass

class EmbitBase:
    def __repr__(self):
        try:
            return type(self).__name__+"(%s)" % str(self)
        except:
            return type(self).__name__+"()"

    @classmethod
    def read_from(cls, stream):
        """All classes should be readable from stream"""
        raise NotImplementedError("%s doesn't implement reading from stream" % type(cls).__name__)

    @classmethod
    def parse(cls, s):
        """Parses a string or a byte sequence"""
        if isinstance(s, str):
            s = s.encode()
        stream = BytesIO(s)
        res = cls.read_from(stream)
        if len(stream.read(1)) > 0:
            raise EmbitError("Unexpected extra bytes")
        return res

    def write_to(self, stream):
        """All classes should be writable to stream"""
        raise NotImplementedError("%s doesn't implement writing to stream" % type(self).__name__)

    def serialize(self):
        stream = BytesIO()
        self.write_to(stream)
        return stream.getvalue()