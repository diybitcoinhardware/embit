"""BIP-32 for blinding keys. Non-standard yet!!!"""
from .. import bip32, ec
from .networks import NETWORKS
import sys
if sys.implementation.name == "micropython":
    import hashlib
else:
    from .util import hashlib

class BlindingHDKey(bip32.HDKey):
    @classmethod
    def from_seed(cls, seed: bytes, version=NETWORKS["liquidv1"]["xprv"]):
        raw = hashlib.hmac_sha512(b"Elements blinding seed", seed)
        private_key = ec.PrivateKey(raw[:32])
        chain_code = raw[32:]
        return cls(private_key, chain_code, version=version)
