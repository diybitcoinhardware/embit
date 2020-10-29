import io
from . import compact
from .script import Script, Witness
from . import hashes
from .util import hashlib

# only SIGHASH_ALL is currently supported
SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3

# FIXME: better to have a parent class
#        that has common methods
def _parse(cls, b: bytes):
    stream = io.BytesIO(b)
    r = cls.read_from(stream)
    if len(stream.read(1)) > 0:
        raise ValueError("Byte array is too long")
    return r


# API similar to bitcoin-cli decoderawtransaction


class Transaction:
    def __init__(self, version=2, vin=[], vout=[], locktime=0):
        self.version = version
        self.locktime = locktime
        # should we copy these?
        self.vin = vin[:]
        self.vout = vout[:]

    @property
    def is_segwit(self):
        # transaction is segwit if at least one input is segwit
        for inp in self.vin:
            if inp.is_segwit:
                return True
        return False

    def serialize(self):
        """Returns the byte serialization of the transaction"""
        res = self.version.to_bytes(4, "little")
        if self.is_segwit:
            res += b"\x00\x01"  # segwit marker and flag
        res += compact.to_bytes(len(self.vin))
        for inp in self.vin:
            res += inp.serialize()
        res += compact.to_bytes(len(self.vout))
        for out in self.vout:
            res += out.serialize()
        if self.is_segwit:
            for inp in self.vin:
                res += inp.witness.serialize()
        res += self.locktime.to_bytes(4, "little")
        return res

    def txid(self):
        h = hashlib.sha256()
        h.update(self.version.to_bytes(4, "little"))
        h.update(compact.to_bytes(len(self.vin)))
        for inp in self.vin:
            h.update(inp.serialize())
        h.update(compact.to_bytes(len(self.vout)))
        for out in self.vout:
            h.update(out.serialize())
        h.update(self.locktime.to_bytes(4, "little"))
        hsh = hashlib.sha256(h.digest()).digest()
        return bytes(reversed(hsh))

    @classmethod
    def parse(cls, b):
        return _parse(cls, b)

    @classmethod
    def read_from(cls, stream):
        ver = int.from_bytes(stream.read(4), "little")
        num_vin = compact.read_from(stream)
        # if num_vin is zero it is a segwit transaction
        is_segwit = num_vin == 0
        if is_segwit:
            marker = stream.read(1)
            if marker != b"\x01":
                raise ValueError("Invalid segwit marker")
            num_vin = compact.read_from(stream)
        vin = []
        for i in range(num_vin):
            vin.append(TransactionInput.read_from(stream))
        num_vout = compact.read_from(stream)
        vout = []
        for i in range(num_vout):
            vout.append(TransactionOutput.read_from(stream))
        if is_segwit:
            for inp in vin:
                inp.witness = Witness.read_from(stream)
        locktime = int.from_bytes(stream.read(4), "little")
        return cls(version=ver, vin=vin, vout=vout, locktime=locktime)

    def hash_prevouts(self):
        h = hashlib.sha256()
        for inp in self.vin:
            h.update(bytes(reversed(inp.txid)))
            h.update(inp.vout.to_bytes(4, "little"))
        return h.digest()

    def hash_sequence(self):
        h = hashlib.sha256()
        for inp in self.vin:
            h.update(inp.sequence.to_bytes(4, "little"))
        return h.digest()

    def hash_outputs(self):
        h = hashlib.sha256()
        for out in self.vout:
            h.update(out.serialize())
        return h.digest()

    def sighash_segwit(self, input_index, script_pubkey, value):
        """check out bip-143"""
        # FIXME: refactor with hashlib.sha256() to reduce memory allocation
        inp = self.vin[input_index]
        h = hashlib.sha256()
        h.update(self.version.to_bytes(4, "little"))
        h.update(hashlib.sha256(self.hash_prevouts()).digest())
        h.update(hashlib.sha256(self.hash_sequence()).digest())
        h.update(bytes(reversed(inp.txid)))
        h.update(inp.vout.to_bytes(4, "little"))
        h.update(script_pubkey.serialize())
        h.update(int(value).to_bytes(8, "little"))
        h.update(inp.sequence.to_bytes(4, "little"))
        h.update(hashlib.sha256(self.hash_outputs()).digest())
        h.update(self.locktime.to_bytes(4, "little"))
        h.update(SIGHASH_ALL.to_bytes(4, "little"))
        return hashlib.sha256(h.digest()).digest()

    def sighash_legacy(self, input_index, script_pubkey):
        h = hashlib.sha256()
        h.update(self.version.to_bytes(4, "little"))
        h.update(compact.to_bytes(len(self.vin)))
        for i, inp in enumerate(self.vin):
            if input_index == i:
                h.update(inp.serialize(script_pubkey))
            else:
                h.update(inp.serialize(Script(b"")))
        h.update(compact.to_bytes(len(self.vout)))
        for out in self.vout:
            h.update(out.serialize())
        h.update(self.locktime.to_bytes(4, "little"))
        h.update(SIGHASH_ALL.to_bytes(4, "little"))
        return hashlib.sha256(h.digest()).digest()


class TransactionInput:
    def __init__(self, txid, vout, script_sig=None, sequence=0xFFFFFFFF, witness=None):
        if script_sig is None:
            script_sig = Script(b"")
        if witness is None:
            witness = Witness([])
        self.txid = txid
        self.vout = vout
        self.script_sig = script_sig
        self.sequence = sequence
        self.witness = witness

    @property
    def is_segwit(self):
        return not (self.witness.serialize() == b"\x00")

    def serialize(self, script_sig=None):
        res = bytes(reversed(self.txid))
        res += self.vout.to_bytes(4, "little")
        if script_sig is None:
            res += self.script_sig.serialize()
        else:
            res += script_sig.serialize()
        res += self.sequence.to_bytes(4, "little")
        return res

    @classmethod
    def parse(cls, b):
        return _parse(cls, b)

    @classmethod
    def read_from(cls, stream):
        txid = bytes(reversed(stream.read(32)))
        vout = int.from_bytes(stream.read(4), "little")
        script_sig = Script.read_from(stream)
        sequence = int.from_bytes(stream.read(4), "little")
        return cls(txid, vout, script_sig, sequence)


class TransactionOutput:
    def __init__(self, value, script_pubkey):
        self.value = int(value)
        self.script_pubkey = script_pubkey

    def serialize(self):
        return self.value.to_bytes(8, "little") + self.script_pubkey.serialize()

    @classmethod
    def parse(cls, b):
        return _parse(cls, b)

    @classmethod
    def read_from(cls, stream):
        value = int.from_bytes(stream.read(8), "little")
        script_pubkey = Script.read_from(stream)
        return cls(value, script_pubkey)
