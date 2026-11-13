from unittest import TestCase

from embit.descriptor.miniscript import AndV, JustOne, Miniscript, V


class CountedScript(Miniscript):
    TYPE = "B"
    PROPS = "z"

    def __init__(self, script):
        super().__init__()
        self.script = script
        self.calls = 0

    def inner_compile(self):
        self.calls += 1
        return self.script


class MiniscriptCompileTest(TestCase):
    def test_verify_wrapper_compiles_child_once(self):
        vectors = [
            (b"\x51\xac", b"\x51\xad"),
            (b"\x51\xae", b"\x51\xaf"),
            (b"\x51\x9c", b"\x51\x9d"),
            (b"\x51\x87", b"\x51\x88"),
            (b"\x51", b"\x51\x69"),
        ]
        for script, expected in vectors:
            child = CountedScript(script)
            self.assertEqual(V(child).compile(), expected)
            self.assertEqual(child.calls, 1)

    def test_nested_verify_wrappers_compile_leaf_once(self):
        depth = 12
        leaf = CountedScript(b"\x51\xb2")  # older(1)
        tree = leaf
        for _ in range(depth):
            tree = AndV(V(tree), JustOne())
        tree.verify()
        self.assertEqual(tree.compile(), b"\x51\xb2" + b"\x69\x51" * depth)
        self.assertEqual(leaf.calls, 1)

    def test_verify_wrapper_recompiles_after_child_changes(self):
        child = CountedScript(b"\x51\xac")
        wrapper = V(child)
        self.assertEqual(wrapper.compile(), b"\x51\xad")
        child.script = b"\x52\xac"
        self.assertEqual(wrapper.compile(), b"\x52\xad")
        self.assertEqual(child.calls, 2)
