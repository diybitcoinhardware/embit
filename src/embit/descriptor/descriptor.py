from io import BytesIO
from .. import script
from ..networks import NETWORKS
from .errors import DescriptorError
from .base import DescriptorBase
from .miniscript import Miniscript, Multi, Sortedmulti, SortedmultiA
from .arguments import Key
from .taptree import TapTree


class Descriptor(DescriptorBase):
    def __init__(
        self,
        miniscript=None,
        sh=False,
        wsh=True,
        key=None,
        wpkh=True,
        taproot=False,
        taptree=None,
    ):
        # TODO: add support for taproot scripts
        # Should:
        # - accept taptree without a key
        # - accept key without taptree
        # - raise if miniscript is not None, but taproot=True
        # - raise if taptree is not None, but taproot=False
        if key is None and miniscript is None and taptree is None:
            raise DescriptorError("Provide a key, miniscript or taptree")
        if miniscript is not None:
            # will raise if can't verify
            miniscript.verify()
            if miniscript.type != "B":
                raise DescriptorError("Top level miniscript should be 'B'")
            # check all branches have the same length
            branches = {
                len(k.branches) for k in miniscript.keys if k.branches is not None
            }
            if len(branches) > 1:
                raise DescriptorError("All branches should have the same length")
        self.sh = sh
        self.wsh = wsh
        self.key = key
        self.miniscript = miniscript
        self.wpkh = wpkh
        self.taproot = taproot
        self.taptree = taptree or TapTree()
        # make sure all keys are either taproot or not
        for k in self.keys:
            k.taproot = taproot

    @property
    def script_len(self):
        if self.taproot:
            return 34  # OP_1 <32:xonly>
        if self.miniscript:
            return len(self.miniscript)
        if self.wpkh:
            return 22  # 00 <20:pkh>
        return 25  # OP_DUP OP_HASH160 <20:pkh> OP_EQUALVERIFY OP_CHECKSIG

    @property
    def num_branches(self):
        return max([k.num_branches for k in self.keys])

    def branch(self, branch_index=None):
        if self.miniscript:
            return type(self)(
                self.miniscript.branch(branch_index),
                self.sh,
                self.wsh,
                None,
                self.wpkh,
                self.taproot,
            )
        else:
            return type(self)(
                None,
                self.sh,
                self.wsh,
                self.key.branch(branch_index),
                self.wpkh,
                self.taproot,
                self.taptree.branch(branch_index),
            )

    @property
    def is_wildcard(self):
        return any([key.is_wildcard for key in self.keys])

    @property
    def is_wrapped(self):
        return self.sh and self.is_segwit

    @property
    def is_legacy(self):
        return not (self.is_segwit or self.is_taproot)

    @property
    def is_segwit(self):
        return (
            (self.wsh and self.miniscript) or (self.wpkh and self.key) or self.taproot
        )

    @property
    def is_pkh(self):
        return self.key is not None and not self.taproot

    @property
    def is_taproot(self):
        return self.taproot

    @property
    def is_basic_multisig(self) -> bool:
        # TODO: should be true for taproot basic multisig with NUMS as internal key
        # Sortedmulti is subclass of Multi
        return bool(self.miniscript and isinstance(self.miniscript, Multi))

    @property
    def is_sorted(self) -> bool:
        return bool(self.is_basic_multisig and isinstance(self.miniscript, Sortedmulti))

    def scriptpubkey_type(self):
        if self.is_taproot:
            return "p2tr"
        if self.sh:
            return "p2sh"
        if self.is_pkh:
            if self.is_legacy:
                return "p2pkh"
            if self.is_segwit:
                return "p2wpkh"
        else:
            return "p2wsh"

    @property
    def brief_policy(self):
        if self.key:
            return "single key"
        if self.is_basic_multisig:
            return (
                str(self.miniscript.args[0])
                + " of "
                + str(len(self.keys))
                + " multisig"
                + (" (sorted)" if self.is_sorted else "")
            )
        return "miniscript"

    @property
    def full_policy(self):
        if self.key or self.is_basic_multisig:
            return self.brief_policy
        s = str(self.miniscript)
        for i, k in enumerate(self.keys):
            s = s.replace(str(k), chr(65 + i))
        return s

    def derive(self, idx, branch_index=None):
        if self.miniscript:
            return type(self)(
                self.miniscript.derive(idx, branch_index),
                self.sh,
                self.wsh,
                None,
                self.wpkh,
                self.taproot,
            )
        else:
            return type(self)(
                None,
                self.sh,
                self.wsh,
                self.key.derive(idx, branch_index),
                self.wpkh,
                self.taproot,
                self.taptree.derive(idx, branch_index),
            )

    def to_public(self):
        if self.miniscript:
            return type(self)(
                self.miniscript.to_public(),
                self.sh,
                self.wsh,
                None,
                self.wpkh,
                self.taproot,
            )
        else:
            return type(self)(
                None,
                self.sh,
                self.wsh,
                self.key.to_public(),
                self.wpkh,
                self.taproot,
                self.taptree.to_public(),
            )

    def owns(self, psbt_scope):
        """Checks if psbt input or output belongs to this descriptor"""
        # we can't check if we don't know script_pubkey
        if psbt_scope.script_pubkey is None:
            return False
        # quick check of script_pubkey type
        if psbt_scope.script_pubkey.script_type() != self.scriptpubkey_type():
            return False
        for pub, der in psbt_scope.bip32_derivations.items():
            # check of the fingerprints
            for k in self.keys:
                if not k.is_extended:
                    continue
                res = k.check_derivation(der)
                if res:
                    idx, branch_idx = res
                    sc = self.derive(idx, branch_index=branch_idx).script_pubkey()
                    # if derivation is found but scriptpubkey doesn't match - fail
                    return sc == psbt_scope.script_pubkey
        for pub, (leafs, der) in psbt_scope.taproot_bip32_derivations.items():
            # check of the fingerprints
            for k in self.keys:
                if not k.is_extended:
                    continue
                res = k.check_derivation(der)
                if res:
                    idx, branch_idx = res
                    sc = self.derive(idx, branch_index=branch_idx).script_pubkey()
                    # if derivation is found but scriptpubkey doesn't match - fail
                    return sc == psbt_scope.script_pubkey
        return False

    def check_derivation(self, derivation_path):
        for k in self.keys:
            # returns a tuple branch_idx, idx
            der = k.check_derivation(derivation_path)
            if der is not None:
                return der
        return None

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
        if self.taproot:
            return script.p2tr(self.key, self.taptree)
        if self.sh:
            return script.p2sh(self.redeem_script())
        if self.wsh:
            return script.p2wsh(self.witness_script())
        if self.miniscript:
            return script.Script(self.miniscript.compile())
        if self.wpkh:
            return script.p2wpkh(self.key)
        return script.p2pkh(self.key)

    def address(self, network=NETWORKS["main"]):
        return self.script_pubkey().address(network)

    @property
    def keys(self):
        if self.key:
            return [self.key]
        return self.miniscript.keys

    @classmethod
    def from_string(cls, desc):
        s = BytesIO(desc.encode())
        res = cls.read_from(s)
        left = s.read()
        if len(left) > 0 and not left.startswith(b"#"):
            raise DescriptorError("Unexpected characters after descriptor: %r" % left)
        return res

    @classmethod
    def read_from(cls, s):
        # starts with sh(wsh()), sh() or wsh()
        start = s.read(7)
        sh = False
        wsh = False
        wpkh = False
        is_miniscript = True
        taproot = False
        taptree = TapTree()
        if start.startswith(b"tr("):
            taproot = True
            s.seek(-4, 1)
        elif start.startswith(b"sh(wsh("):
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
            raise ValueError("Invalid descriptor (starts with '%s')" % start.decode())
        # taproot always has a key, and may have taptree miniscript
        if taproot:
            miniscript = None
            key = Key.read_from(s, taproot=taproot)
            nbrackets = 1 + int(sh)
            c = s.read(1)
            # TODO: should it be ok to pass just taptree without a key?
            # check if we have taptree after the key
            if c != b",":
                s.seek(-1, 1)
            else:
                taptree = TapTree.read_from(s)
        elif is_miniscript:
            miniscript = Miniscript.read_from(s)
            key = None
            nbrackets = int(sh) + int(wsh)
        # single key for sure
        else:
            miniscript = None
            key = Key.read_from(s, taproot=taproot)
            nbrackets = 1 + int(sh)
        end = s.read(nbrackets)
        if end != b")" * nbrackets:
            raise ValueError(
                "Invalid descriptor (expected ')' but ends with '%s')" % end.decode()
            )
        return cls(
            miniscript,
            sh=sh,
            wsh=wsh,
            key=key,
            wpkh=wpkh,
            taproot=taproot,
            taptree=taptree,
        )

    def to_string(self):
        if self.taproot:
            if self.taptree:
                return "tr(%s,%s)" % (self.key, self.taptree)
            return "tr(%s)" % self.key
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
