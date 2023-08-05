from io import BytesIO
from ..base import EmbitBase


class DescriptorBase(EmbitBase):
    """
    Descriptor is purely text-based, so parse/serialize do
    the same as from/to_string, just returning ascii bytes
    instead of ascii string.
    """

    @classmethod
    def from_string(cls, s: str, *args, **kwargs):
        return cls.parse(s.encode(), *args, **kwargs)

    def serialize(self, *args, **kwargs) -> bytes:
        stream = BytesIO()
        self.write_to(stream)
        return stream.getvalue()

    def to_string(self, *args, **kwargs) -> str:
        return self.serialize().decode()
