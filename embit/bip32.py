from . import ec
from .networks import NETWORKS
from . import base58
from .util import hashlib
import io
from .util import secp256k1
from . import hashes
from binascii import hexlify


class HDKey:
    """ HD Private or Public key """

    def __init__(
        self,
        key,
        chain_code: bytes,
        version=None,
        depth: int = 0,
        fingerprint: bytes = b"\x00\x00\x00\x00",
        child_number: int = 0,
    ):
        self.key = key
        if len(key.serialize()) != 32 and len(key.serialize()) != 33:
            raise ValueError("Invalid key. Should be private or compressed public")
        if version is not None:
            self.version = version[:]
        else:
            if len(key.serialize()) == 32:
                self.version = NETWORKS["main"]["xprv"]
            else:
                self.version = NETWORKS["main"]["xpub"]
        self.chain_code = chain_code[:]
        self.depth = depth
        self.fingerprint = fingerprint[:]
        self.child_number = child_number
        # check that base58[1:4] is "prv" or "pub"
        if self.is_private and self.to_base58()[1:4] != "prv":
            raise ValueError("Invalid version")
        if not self.is_private and self.to_base58()[1:4] != "pub":
            raise ValueError("Invalid version")

    @classmethod
    def from_seed(cls, seed: bytes, version=NETWORKS["main"]["xprv"]):
        """Creates a root private key from 64-byte seed"""
        raw = hashlib.hmac_sha512(b"Bitcoin seed", seed)
        private_key = ec.PrivateKey(raw[:32])
        chain_code = raw[32:]
        return cls(private_key, chain_code, version=version)

    @classmethod
    def from_base58(cls, s: str):
        b = base58.decode_check(s)
        return cls.parse(b)

    @property
    def is_private(self) -> bool:
        """ checks if the HDKey is private or public """
        return len(self.key.serialize()) == 32

    def serialize(self, version=None) -> bytes:
        if version is None:
            version = self.version
        b = version + bytes([self.depth]) + self.fingerprint
        b += self.child_number.to_bytes(4, "big")
        b += self.chain_code
        if self.is_private:
            b += b"\x00" + self.key.serialize()
        else:
            b += self.key.serialize()
        return b

    def to_base58(self, version=None) -> str:
        b = self.serialize(version)
        return base58.encode_check(b)

    @classmethod
    def parse(cls, b: bytes):
        stream = io.BytesIO(b)
        hd = cls.read_from(stream)
        if len(stream.read(1)) > 0:
            raise ValueError("Byte array is too long")
        return hd

    @classmethod
    def read_from(cls, stream):
        version = stream.read(4)
        depth = stream.read(1)[0]
        fingerprint = stream.read(4)
        child_number = int.from_bytes(stream.read(4), "big")
        chain_code = stream.read(32)
        k = stream.read(33)
        if k[0] == 0:
            key = ec.PrivateKey.parse(k[1:])
        else:
            key = ec.PublicKey.parse(k)

        if len(version) < 4 or len(fingerprint) < 4 or len(chain_code) < 32:
            raise ValueError("Not enough bytes")
        hd = cls(
            key,
            chain_code,
            version=version,
            depth=depth,
            fingerprint=fingerprint,
            child_number=child_number,
        )
        subver = hd.to_base58()[1:4]
        if subver != "prv" and subver != "pub":
            raise ValueError("Invalid version")
        return hd

    def to_public(self, version=None):
        if not self.is_private:
            raise RuntimeError("Already public")
        if version is None:
            # detect network
            for net in NETWORKS:
                for k in NETWORKS[net]:
                    if "prv" in k and NETWORKS[net][k] == self.version:
                        # xprv -> xpub, zprv -> zpub etc
                        version = NETWORKS[net][k.replace("prv", "pub")]
                        break
        if version is None:
            raise RuntimeError(
                "Can't find proper version. Provide it with version keyword"
            )
        return self.__class__(
            self.key.get_public_key(),
            self.chain_code,
            version=version,
            depth=self.depth,
            fingerprint=self.fingerprint,
            child_number=self.child_number,
        )

    def sec(self) -> bytes:
        """Returns SEC serialization of the public key"""
        return self.key.sec()

    def child(self, index: int, hardened: bool = False):
        """Derives a child HDKey"""
        if index > 0xFFFFFFFF:
            raise ValueError("Index should be less then 2^32")
        if hardened and index < 0x80000000:
            index += 0x80000000
        if index >= 0x80000000:
            hardened = True
        if hardened and not self.is_private:
            raise ValueError("Can't do hardened with public key")

        # we need pubkey for fingerprint anyways
        sec = self.sec()
        fingerprint = hashes.hash160(sec)[:4]
        if hardened:
            data = b"\x00" + self.key.serialize() + index.to_bytes(4, "big")
        else:
            data = sec + index.to_bytes(4, "big")
        raw = hashlib.hmac_sha512(self.chain_code, data)
        secret = raw[:32]
        chain_code = raw[32:]
        if self.is_private:
            secret = secp256k1.ec_privkey_add(secret, self.key.serialize())
            key = ec.PrivateKey(secret)
        else:
            # copy of internal secp256k1 point structure
            point = self.key._point[:]
            point = secp256k1.ec_pubkey_add(point, secret)
            key = ec.PublicKey(point)
        return HDKey(
            key,
            chain_code,
            version=self.version[:],
            depth=self.depth + 1,
            fingerprint=fingerprint,
            child_number=index,
        )

    def derive(self, path):
        """ path: int array or a string starting with m/ """
        if isinstance(path, str):
            # string of the form m/44h/0'/ind
            path = parse_path(path)
        child = self
        for idx in path:
            child = child.child(idx)
        return child

    def sign(self, msg_hash: bytes) -> ec.Signature:
        """signs a hash of the message with the private key"""
        if not self.is_private:
            raise RuntimeError("HD public key can't sign")
        return self.key.sign(msg_hash)

    def verify(self, sig: ec.Signature, msg_hash: bytes) -> bool:
        """Verifies a signature agains 32-byte message hash"""
        if self.is_private:
            return self.key.get_public_key().verify(sig, msg_hash)
        else:
            return self.key.verify(sig, msg_hash)

    def __hash__(self):
        return hash(self.serialize())

    def __eq__(self, other):
        # skip version
        return self.serialize()[4:] == other.serialize()[4:]

    def __ne__(self, other):
        return not self.__eq__(other)


def detect_version(path: str, default="xprv", network=None) -> bytes:
    """
    Detects slip-132? version from the path for certain network.
    Trying to be smart, use if you want, but with care.
    """
    key = default
    net = network
    if network is None:
        net = NETWORKS["main"]
    arr = parse_path(path)
    if len(arr) == 0:
        return network[key]
    if arr[0] == 0x80000000 + 84:
        key = "z" + default[1:]
    elif arr[0] == 0x80000000 + 49:
        key = "y" + default[1:]
    elif arr[0] == 0x80000000 + 48:
        if len(arr) >= 4:
            if arr[3] == 0x80000000 + 1:
                key = "Y" + default[1:]
            elif arr[3] == 0x80000000 + 2:
                key = "Z" + default[1:]
    if network is None and len(arr) > 1 and arr[1] == 0x80000000 + 1:
        net = NETWORKS["test"]
    return net[key]


def parse_path(path: str) -> list:
    """converts derivation path of the form m/44h/1'/0'/0/32 to int array"""
    arr = path.split("/")
    if arr[0] == "m":
        arr = arr[1:]
    if len(arr) == 0:
        return []
    if arr[-1] == "":
        # trailing slash
        arr = arr[:-1]
    for i, e in enumerate(arr):
        if e[-1] == "h" or e[-1] == "'":
            arr[i] = int(e[:-1]) + 0x80000000
        else:
            arr[i] = int(e)
    return arr


def path_to_str(path: list, fingerprint=None) -> str:
    s = "m" if fingerprint is None else hexlify(fingerprint).decode()
    for el in path:
        if el >= 0x80000000:
            s += "/%dh" % (el - 0x80000000)
        else:
            s += "/%d" % el
    return s
