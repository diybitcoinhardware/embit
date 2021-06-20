"""
PSBTView class is RAM-friendly implementation of PSBT that reads required data from a stream on request.
The PSBT transaction itself passed to the class is a readable stream - it can be a file stream or a BytesIO object.
When using files make sure they are in trusted storage - when using SD card or other untrusted source make sure
to copy the file to a trusted media (flash, QSPI or SPIRAM for example).
Otherwise you expose yourself to time-of-check-time-of-use style of attacks where SD card MCU can trick you
to sign a wrong transactions.
"""
from .psbt import *

def skip_string(stream) -> bytes:
    l = compact.read_from(stream)
    stream.seek(l, 1)
    return len(compact.to_bytes(l)) + l

class PSBTView:
    """
    Constructor shouldn't be used directly. PSBTView.view_from(stream) should be used instead.
    Either version should be 2 or tx_offset should be int, otherwise you get an error
    """
    # for subclasses like PSET
    MAGIC = b"psbt\xff"
    # PSBTIN_CLS = InputScopeView
    # PSBTOUT_CLS = OutputScopeView
    # TX_CLS = TransactionView

    def __init__(self, stream,
            num_inputs, num_outputs,
            offset, version=None,
            tx_offset=None):
        if version != 2 and tx_offset
        self.stream = stream
        # by default we use provided offset, tell() or 0 as default value
        self.offset = offset or 0
        self.num_inputs = num_inputs
        self.num_outputs = num_outputs

    @classmethod
    def view_from(cls, stream, offset=None):
        if offset is None and hasattr(stream, 'tell'):
            offset = offset.tell()
        offset = offset or 0
        # current offset
        cur = offset
        # check magic
        if stream.read(len(cls.MAGIC)) != cls.MAGIC:
            raise PSBTError("Invalid PSBT magic")
        cur += len(cls.MAGIC)
        # first we parse the global scope and see if we have tx there
        version = None
        num_inputs = None
        num_outputs = None
        tx_offset = None
        while True:
            # read key and update cursor
            key = read_string(stream)
            cur += len(key) + len(compact.to_bytes(len(key)))
            # separator
            if len(key) == 0:
                break
            if key in [b"\xfb", b"\x04", b"\x05"]:
                value = read_string(stream)
                cur += len(value) + len(compact.to_bytes(len(value)))
                if key == b"\xfb":
                    version = int.from_bytes(value, 'little')
                elif key == b"\x04":
                    num_inputs = compact.from_bytes(value)
                elif key == b"\x05":
                    num_outputs = compact.from_bytes(value)
            elif key == b"\x00":
                # we found global transaction
                assert version != 2
                assert (num_inputs is None) and (num_outputs is None)
                l = compact.read_from(stream)
                cur += len(compact.to_bytes(l))
                tx_offset = cur
                cur += skip_string(stream)
            else:
                cur += skip_string(stream)
        if None in [version or tx_offset, num_inputs, num_outputs]:
            raise PSBTError("Missing something important in PSBT")
        return cls(stream, num_inputs, num_outputs, offset, version, tx_offset)
