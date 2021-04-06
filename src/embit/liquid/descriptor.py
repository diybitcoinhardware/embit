from ..descriptor.descriptor import *
from .networks import NETWORKS
from .addresses import address
from . import slip77
from ..hashes import tagged_hash, sha256
from ..ec import PrivateKey, PublicKey, secp256k1

class LDescriptor(Descriptor):
    """Liquid descriptor that supports blinded() wrapper"""
    def __init__(self, *args, blinding_key=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._blinding_key = blinding_key

    @property
    def is_blinded(self):
        return self._blinding_key is not None    

    def address(self, network=NETWORKS["liquidv1"]):
        sc = self.script_pubkey()
        if not self.is_blinded:
            return sc.address(network)
        bkey = self._blinding_key.get_blinding_key(sc)
        return address(sc, bkey, network)

    def derive(self, idx, branch_index=None):
        d = super().derive(idx, branch_index)
        if self.is_blinded:
            blinding_key = self._blinding_key.derive(idx, branch_index)
            d._blinding_key = blinding_key
        return d

    @classmethod
    def read_from(cls, s):
        # starts with blinded(K,...) or directly with sh(wsh()), sh() or wsh()
        start = s.read(8)
        if not start.startswith(b"blinded("):
            s.seek(-8, 1)
            d = Descriptor.read_from(s)
            return cls(d.miniscript, sh=d.sh, wsh=d.wsh, key=d.key, wpkh=d.wpkh, blinding_key=None)

        blinding_key = BlindingKey.read_from(s)
        if s.read(1) != b",":
            raise DescriptorError("Missing bitcoin descriptor")
        d = Descriptor.read_from(s)
        if s.read(1) != b")":
            raise DescriptorError("Missing ending bracket")
        if not blinding_key.slip77:
            if blinding_key.is_wildcard != d.is_wildcard:
                raise DescriptorError("Wildcards mismatch in blinded key and descriptor")
            if blinding_key.num_branches != d.num_branches:
                raise DescriptorError("Branches mismatch in blinded key and descriptor")
        return cls(d.miniscript, sh=d.sh, wsh=d.wsh, key=d.key, wpkh=d.wpkh, blinding_key=blinding_key)

    def to_string(self):
        res = super().to_string()
        if self.is_blinded:
            res = "blinded(%s,%s)" % (self._blinding_key, res)
        return res

class BlindingKey(DescriptorBase):
    def __init__(self, key, slip77=False):
        self.key = key
        self.slip77 = slip77

    def derive(self, idx, branch_index=None):
        if self.slip77:
            return self
        else:
            return type(self)(self.key.derive(idx, branch_index), self.slip77)

    @property
    def is_wildcard(self):
        if not self.slip77:
            return self.key.is_wildcard

    @property
    def num_branches(self):
        if not self.slip77:
            return self.key.num_branches

    def get_blinding_key(self, sc):
        if self.slip77:
            return slip77.blinding_key(self.key.private_key, sc)
        # if not slip77 - make a script tweak to the key
        tweak = tagged_hash("elements/blindingkey", sc.data)
        if self.key.is_private:
            return ec.PrivateKey(secp256k1.ec_privkey_add(self.key.secret, tweak))
        else:
            return ec.PublicKey(secp256k1.ec_pubkey_add(secp256k1.ec_pubkey_parse(self.key.sec()), tweak))

    @classmethod
    def read_from(cls, s):
        start = s.read(7)
        slip77 = False
        if start.startswith(b"slip77("):
            slip77 = True
            key = Key.read_from(s)
            if key.is_extended or not key.is_private:
                raise DescriptorError("SLIP-77 key should be a WIF private key")
            if s.read(1) != b")":
                raise DescriptorError("Missing closing bracket after slip77")
        elif start.startswith(b"musig("):
            s.seek(-7, 1)
            key = MuSigKey.read_from(s)
        else:
            s.seek(-7, 1)
            key = Key.read_from(s)
        return cls(key, slip77)

    def to_string(self):
        if self.slip77:
            return "slip77(%s)" % self.key
        else:
            return str(self.key)

class MuSigKey(DescriptorBase):
    def __init__(self, keys):
        self.keys = keys

    def derive(self, idx, branch_index=None):
        return type(self)([k.derive(idx, branch_index) for k in self.keys])

    def to_string(self):
        return "musig(%s)" % (",".join([str(k) for k in self.keys]))

    @property
    def is_wildcard(self):
        return any([key.is_wildcard for key in self.keys])

    @property
    def num_branches(self):
        return max([k.num_branches for k in self.keys])

    @classmethod
    def read_from(cls, s):
        start = s.read(6)
        if start != b"musig(":
            raise DescriptorError("Expected musig()")
        keys = []
        while True:
            keys.append(Key.read_from(s))
            c = s.read(1)
            if c == b")":
                break
            if c != b",":
                raise DescriptorError("Expected , in musig")
        return cls(keys)

    @property
    def is_private(self):
        return all([k.is_private for k in self.keys])

    @property
    def secret(self):
        # TODO: make a real musig using secp.musig module
        # For now just addition of the keys
        s = self.keys[0].secret
        for k in self.keys[1:]:
            s = secp256k1.ec_privkey_add(s, k.secret)
        return s

    def sec(self):
        # TODO: make a real musig using secp.musig module
        # For now just addition of the keys
        pubs = [secp256k1.ec_pubkey_parse(k.sec()) for k in self.keys]
        pub = secp256k1.ec_pubkey_combine(*pubs)
        return PublicKey(pub).sec()
    