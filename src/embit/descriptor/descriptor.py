from binascii import hexlify, unhexlify
from io import BytesIO
from .. import hashes, compact, ec, bip32, script
from ..networks import NETWORKS
from .errors import DescriptorError
from .base import DescriptorBase
from .miniscript import Miniscript
from .arguments import Key

class Descriptor(DescriptorBase):
    def __init__(self, miniscript=None, sh=False, wsh=True, key=None, wpkh=True):
        if key is None and miniscript is None:
            raise DescriptorError("Provide either miniscript or a key")
        if miniscript is not None:
            # will raise if can't verify
            miniscript.verify()
            if miniscript.type != "B":
                raise DescriptorError("Top level miniscript should be 'B'")
            branches = [k.branches for k in miniscript.keys]
            branch = None
            for b in branches:
                if b is not None:
                    if branch is None:
                        branch = b
                    else:
                        if len(branch) != len(b):
                            raise DescriptorError("All branches should have the same length")
        self.sh = sh
        self.wsh = wsh
        self.key = key
        self.miniscript = miniscript
        self.wpkh = wpkh

    @property
    def is_nested(self):
        return self.sh

    @property
    def is_segwit(self):
        return (self.wsh and self.miniscript) or (self.wpkh and self.key)

    @property
    def is_pkh(self):
        return self.key is not None    

    @property
    def is_basic_multisig(self):
        return self.miniscript and self.miniscript.NAME in ["multi", "sortedmulti"]

    @property
    def is_sorted(self):
        return self.is_basic_multisig and self.miniscript.NAME == "sortedmulti"    

    def derive(self, idx, branch_index=None):
        if self.miniscript:
            return type(self)(self.miniscript.derive(idx, branch_index), self.sh, self.wsh, None, self.wpkh)
        else:
            return type(self)(None, self.sh, self.wsh, self.key.derive(idx, branch_index), self.wpkh)

    def witness_script(self):
        if self.wsh and self.miniscript is not None:
            return script.Script(self.miniscript.compile())

    def redeem_script(self):
        if not self.sh:
            return None
        if self.miniscript:
            if not self.wsh:
                return script.Script(self.miniscript.compile())
            else:
                return script.p2wsh(script.Script(self.miniscript.compile()))
        else:
            return script.p2wpkh(self.key)

    def script_pubkey(self):
        # covers sh-wpkh, sh and sh-wsh
        if self.sh:
            return script.p2sh(self.redeem_script())
        if self.wsh:
            return script.p2wsh(self.witness_script())
        if self.miniscript:
            return script.Script(self.miniscript.compile())
        if self.wpkh:
            return script.p2wpkh(self.key)
        return script.p2pkh(self.key)

    def address(self, network=NETWORKS['main']):
        return self.script_pubkey().address(network)

    @property
    def keys(self):
        if self.key:
            return [self.key]
        return self.miniscript.keys

    @classmethod
    def from_string(cls, desc):
        s = BytesIO(desc.encode())
        return cls.read_from(s)

    @classmethod
    def read_from(cls, s):
        # starts with sh(wsh()), sh() or wsh()
        start = s.read(7)
        sh = False
        wsh = False
        wpkh = False
        is_miniscript = True
        if start.startswith(b"sh(wsh("):
            sh = True
            wsh = True
        elif start.startswith(b"wsh("):
            sh = False
            wsh = True
            s.seek(-3, 1)
        elif start.startswith(b"sh(wpkh"):
            is_miniscript = False
            sh = True
            wpkh = True
            assert s.read(1) == b"("
        elif start.startswith(b"wpkh("):
            is_miniscript = False
            wpkh = True
            s.seek(-2, 1)
        elif start.startswith(b"pkh("):
            is_miniscript = False
            s.seek(-3, 1)
        elif start.startswith(b"sh("):
            sh = True
            wsh = False
            s.seek(-4, 1)
        else:
            raise ValueError("Invalid descriptor")
        if is_miniscript:
            miniscript = Miniscript.read_from(s)
            key = None
            nbrackets = int(sh)+int(wsh)
        else:
            miniscript = None
            key = Key.read_from(s)
            nbrackets = 1 + int(sh)
        end = s.read(nbrackets)
        if end != b")"*nbrackets:
            raise ValueError("Invalid descriptor")
        return cls(miniscript, sh=sh, wsh=wsh, key=key, wpkh=wpkh)

    def to_string(self):
        if self.miniscript is not None:
            res = str(self.miniscript)
            if self.wsh:
                res = "wsh(%s)" % res
        else:
            if self.wpkh:
                res = "wpkh(%s)" % self.key
            else:
                res = "pkh(%s)" % self.key
        if self.sh:
            res = "sh(%s)" % res
        return res
