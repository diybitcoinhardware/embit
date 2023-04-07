from .errors import MiniscriptError
from .base import DescriptorBase
from .miniscript import Miniscript
from ..hashes import tagged_hash
from ..script import Script


class TapLeaf(DescriptorBase):

    def __init__(self, miniscript=None, version = 0xc0):
        self.miniscript = miniscript
        self.version = version

    def __str__(self):
        return str(self.miniscript)

    @classmethod
    def read_from(cls, s):
        ms = Miniscript.read_from(s)
        return cls(ms)

    def serialize(self):
        if self.miniscript is None:
            return b""
        return bytes([self.version])+Script(self.miniscript.compile()).serialize()

    @property
    def keys(self):
        return self.miniscript.keys

    def derive(self, *args, **kwargs):
        if self.miniscript is None:
            return type(self)(None, version=self.version)
        return type(self)(
            self.miniscript.derive(*args, **kwargs),
            self.version,
        )

    def branch(self, *args, **kwargs):
        if self.miniscript is None:
            return type(self)(None, version=self.version)
        return type(self)(
            self.miniscript.branch(*args, **kwargs),
            self.version,
        )

    def to_public(self, *args, **kwargs):
        if self.miniscript is None:
            return type(self)(None, version=self.version)
        return type(self)(
            self.miniscript.to_public(*args, **kwargs),
            self.version,
        )

def _tweak_helper(tree):
    # https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
    if isinstance(tree, TapTree):
        tree = tree.tree
    if isinstance(tree, TapLeaf):
        # one leaf on this branch
        h = tagged_hash("TapLeaf", tree.serialize())
        return ([(tree, b"")], h)
    left, left_h = _tweak_helper(tree[0])
    right, right_h = _tweak_helper(tree[1])
    ret = (
        [(leaf, c + right_h) for leaf, c in left] +
        [(leaf, c + left_h) for leaf, c in right]
    )
    if right_h < left_h:
        left_h, right_h = right_h, left_h
    return (ret, tagged_hash("TapBranch", left_h + right_h))

class TapTree(DescriptorBase):
    def __init__(self, tree=None):
        """tree can be None, TapLeaf or a tuple (taptree, taptree)"""
        self.tree = tree
        # make sure all keys are taproot
        for k in self.keys:
            k.taproot = True

    def __bool__(self):
        return bool(self.tree)

    def tweak(self):
        if self.tree is None:
            return b""
        _, h = _tweak_helper(self.tree)
        return h

    @property
    def keys(self):
        if self.tree is None:
            return []
        if isinstance(self.tree, TapLeaf):
            return self.tree.keys
        left, right = self.tree
        return left.keys + right.keys

    @classmethod
    def read_from(cls, s):
        c = s.read(1)
        if len(c) == 0:
            return cls()
        if c == b"{": # more than one miniscript
            left = cls.read_from(s)
            c = s.read(1)
            if c == b"}":
                return left
            if c != b",":
                raise MiniscriptError("Invalid taptree syntax: expected ','")
            right = cls.read_from(s)
            if s.read(1) != b"}":
                raise MiniscriptError("Invalid taptree syntax: expected '}'")
            return cls((left, right))
        s.seek(-1, 1)
        ms = TapLeaf.read_from(s)
        return cls(ms)

    def derive(self, *args, **kwargs):
        if self.tree is None:
            return type(self)(None)
        if isinstance(self.tree, TapLeaf):
            return type(self)(self.tree.derive(*args, **kwargs))
        left, right = self.tree
        return type(self)((left.derive(*args, **kwargs), right.derive(*args, **kwargs)))

    def branch(self, *args, **kwargs):
        if self.tree is None:
            return type(self)(None)
        if isinstance(self.tree, TapLeaf):
            return type(self)(self.tree.branch(*args, **kwargs))
        left, right = self.tree
        return type(self)((left.branch(*args, **kwargs), right.branch(*args, **kwargs)))

    def to_public(self, *args, **kwargs):
        if self.tree is None:
            return type(self)(None)
        if isinstance(self.tree, TapLeaf):
            return type(self)(self.tree.to_public(*args, **kwargs))
        left, right = self.tree
        return type(self)((left.to_public(*args, **kwargs),
                           right.to_public(*args, **kwargs)))

    def __str__(self):
        if self.tree is None:
            return ""
        if isinstance(self.tree, TapLeaf):
            return str(self.tree)
        (left, right) = self.tree
        return "{%s,%s}" % (left, right)
