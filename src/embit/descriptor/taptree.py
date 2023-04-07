from .errors import MiniscriptError
from .base import DescriptorBase
from .miniscript import Miniscript

class TapTree(DescriptorBase):
    def __init__(self, tree=None):
        """tree can be None, Miniscript or a tuple (taptree, taptree)"""
        self.tree = tree

    @property
    def keys(self):
        # TODO: implement
        return [] 

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
        ms = Miniscript.read_from(s)
        return cls(ms)

    def __str__(self):
        if self.tree is None:
            return ""
        if isinstance(self.tree, Miniscript):
            return str(self.tree)
        (left, right) = self.tree
        return "{%s,%s}" % (left, right)
