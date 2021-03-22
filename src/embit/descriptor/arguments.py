from binascii import hexlify, unhexlify
from .base import DescriptorBase, read_until
from .errors import ArgumentError
from .. import bip32, ec, compact, hashes

class KeyOrigin:
    def __init__(self, fingerprint: bytes, derivation: list):
        self.fingerprint = fingerprint
        self.derivation = derivation

    @classmethod
    def from_string(cls, s:str):
        arr = s.split("/")
        mfp = unhexlify(arr[0])
        assert len(mfp) == 4
        arr[0] = "m"
        path = "/".join(arr)
        derivation = bip32.parse_path(path)
        return cls(mfp, derivation)

    def __str__(self):
        return bip32.path_to_str(self.derivation, fingerprint=self.fingerprint)


class Derivation(DescriptorBase):
    # xpub/{0,1}/* - {0,1} is a set of allowed branches, wildcard * is stored as None
    def __init__(self, indexes=[[0,1], None]):
        # check only one wildcard and only one set is in the derivation
        if len([i for i in indexes if i is None]) > 1:
            raise ArgumentError("Only one wildcard is allowed")
        if len([i for i in indexes if isinstance(i,list)]) > 1:
            raise ArgumentError("Only one wildcard is allowed")
        self.indexes = indexes

    def fill(self, idx, branch_index=None):
        if idx < 0 or idx >= 0x80000000:
            raise ArgumentError("Hardened indexes are not allowed in wildcard")
        arr = [i for i in self.indexes]
        for i, el in enumerate(arr):
            if el is None:
                arr[i] = idx
            if isinstance(el, list):
                if branch_index is None:
                    arr[i] = el[0]
                else:
                    if branch_index < 0 or branch_index >= len(el):
                        raise ArgumentError("Invalid branch index")
                    arr[i] = el[branch_index]
        return arr

    @property
    def branches(self):
        for el in self.indexes:
            if isinstance(el, list):
                return el
        return None

    @property
    def has_hardend(self):
        for idx in self.indexes:
            if isinstance(idx, int) and idx >= 0x80000000:
                return True
            if isinstance(idx, list) and len([i for i in idx if i >= 0x80000000]) > 0:
                return True
        return False

    @classmethod
    def from_string(cls, der:str, allow_hardened=False, allow_set=True):
        if len(der) == 0:
            return None
        indexes = [cls.parse_element(d, allow_hardened, allow_set) for d in der.split("/")]
        return cls(indexes)

    @classmethod
    def parse_element(cls, d:str, allow_hardened=False, allow_set=True):
        # wildcard
        if d == "*":
            return None
        # branch set
        if d[0] == "{" and d[-1] == "}":
            if not allow_set:
                raise ArgumentError("Set is not allowed in derivation %s" % d)
            return [cls.parse_element(dd, allow_hardened, allow_set=False) for dd in d[1:-1].split(",")]
        idx = 0
        if d[-1] == "h":
            if not allow_hardened:
                raise ArgumentError("Hardened derivation is not allowed in %s" % d)
            idx = 0x80000000
            d = d[:-1]
        i = int(d)
        if i < 0 or i >= 0x80000000:
            raise ArgumentError("Derivation index can be in a range [0, 0x80000000)")
        return idx+i

    def __str__(self):
        r = ""
        for idx in self.indexes:
            if idx is None:
                r += "/*"
            if isinstance(idx, int):
                if idx >= 0x80000000:
                    r += "/%dh" % (idx-0x80000000)
                else:
                    r += "/%d" % idx
            if isinstance(idx, list):
                r += "/{"
                r += ",".join([str(i) if i < 0x80000000 else str(i-0x80000000)+"h" for i in idx])
                r += "}"
        return r

class Key(DescriptorBase):
    def __init__(self, key, origin=None, derivation=None):
        self.origin = origin
        self.k = key
        if not hasattr(key, "derive") and derivation is not None:
            raise ArgumentError("Key %s doesn't support derivation" % key)
        self.derivation = derivation

    @classmethod
    def read_from(cls, s):
        first = s.read(1)
        origin = None
        if first == b"[":
            prefix, char = read_until(s, b"]")
            if char != b"]":
                raise ArgumentError("Invalid key - missing ]")
            origin = KeyOrigin.from_string(prefix.decode())
        else:
            s.seek(-1, 1)
        k, char = read_until(s, b",)/")
        der = b""
        # there is a following derivation
        if char == b"/":
            der, char = read_until(s, b"{,)")
            # we get a set of possible branches: {a,b,c...}
            if char == b"{":
                der += b"{"
                branch, char = read_until(s, b"}")
                if char is None:
                    raise ArgumentError("Failed reading the key, missing }")
                der += branch+b"}"
                rest, char = read_until(s, b",)")
                der += rest
        if char is not None:
            s.seek(-1, 1)
        # parse key
        k = cls.parse_key(k)
        # parse derivation
        allow_hardened = isinstance(k, bip32.HDKey) and isinstance(k.key, ec.PrivateKey)
        derivation = Derivation.from_string(der.decode(), allow_hardened=allow_hardened)
        return cls(k, origin, derivation)

    @classmethod
    def parse_key(cls, k:bytes):
        # convert to string
        k = k.decode()
        if len(k) in [66, 130] and k[:2] in ["02", "03", "04"]:
            # bare public key
            return ec.PublicKey.parse(unhexlify(k))
        elif k[1:4] in ["pub", "prv"]:
            # bip32 key
            return bip32.HDKey.from_base58(k)
        else:
            return ec.PrivateKey.from_wif(k)

    def sec(self):
        return self.k.sec()

    def serialize(self):
        return self.sec()

    def compile(self):
        d = self.serialize()
        return compact.to_bytes(len(d))+d

    @property
    def prefix(self):
        if self.origin:
            return "[%s]" % self.origin
        return ""

    @property
    def suffix(self):
        return "" if self.derivation is None else str(self.derivation)

    @property
    def can_derive(self):
        return self.derivation is not None and hasattr(self.k, "derive")

    @property
    def branches(self):
        return self.derivation.branches if self.derivation else None

    def derive(self, idx, branch_index=None):
        # nothing to derive
        if self.derivation is None:
            return self
        der = self.derivation.fill(idx, branch_index=branch_index)
        k = self.k.derive(der)
        origin = KeyOrigin(self.origin.fingerprint, self.origin.derivation + der)
        # empty derivation
        derivation = None
        return type(self)(k, origin, derivation)

    def to_string(self):
        if isinstance(self.k, ec.PublicKey):
            return self.prefix + hexlify(self.k.sec()).decode()
        if isinstance(self.k, bip32.HDKey):
            return self.prefix + self.k.to_base58() + self.suffix
        if isinstance(self.k, ec.PrivateKey):
            return self.prefix + self.k.wif()
        return self.prefix + self.k

    @classmethod
    def from_string(cls, s):
        return cls.parse(s.encode())

class KeyHash(Key):
    @classmethod
    def parse_key(cls, k:bytes):
        # convert to string
        k = k.decode()
        # raw 20-byte hash
        if len(k) == 40:
            return k
        if len(k) in [66, 130] and k[:2] in ["02", "03", "04"]:
            # bare public key
            return ec.PublicKey.parse(unhexlify(k))
        elif k[1:4] in ["pub", "prv"]:
            # bip32 key
            return bip32.HDKey.from_base58(k)
        else:
            return ec.PrivateKey.from_wif(k)

    def serialize(self):
        if isinstance(self.k, str):
            return unhexlify(self.k)
        return hashes.hash160(self.k.sec())

    def compile(self):
        d = self.serialize()
        return compact.to_bytes(len(d))+d

class Number(DescriptorBase):
    def __init__(self, num):
        self.num = num

    @classmethod
    def read_from(cls, s):
        num = 0
        char = s.read(1)
        while char in b"0123456789":
            num = 10*num + int(char.decode())
            char = s.read(1)
        s.seek(-1, 1)
        return cls(num)

    def compile(self):
        if self.num == 0:
            return b"\x00"
        if self.num <= 16:
            return bytes([80+self.num])
        b = self.num.to_bytes(32, 'little').rstrip(b"\x00")
        if b[-1] >= 128:
            b += b"\x00"
        return bytes([len(b)]) + b

    def __str__(self):
        return "%d" % self.num

class Raw(DescriptorBase):
    def __init__(self, raw):
        if len(raw) != self.LEN*2:
            raise ArgumentError("Invalid raw element length: %d" % len(raw))
        self.raw = unhexlify(raw)

    @classmethod
    def read_from(cls, s):
        return cls(s.read(2*cls.LEN).decode())

    def __str__(self):
        return hexlify(self.raw).decode()

    def compile(self):
        return compact.to_bytes(len(self.raw))+self.raw

class Raw32(Raw):
    LEN = 32

class Raw20(Raw):
    LEN = 20
