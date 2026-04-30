from unittest import TestCase
from embit.script import Script, p2wpkh, p2sh, p2pkh, p2tr
from embit.ec import PrivateKey
from embit.hashes import hash160


class ScriptTest(TestCase):
    def test_from_addr(self):
        pk = PrivateKey(b"\x11" * 32)
        scripts = [
            p2wpkh(pk),
            p2pkh(pk),
            p2sh(p2wpkh(pk)),
            p2tr(pk),
        ]
        for sc in scripts:
            self.assertEqual(sc, Script.from_address(sc.address()))

    def test_push(self):
        pk = PrivateKey(b"\x11" * 32)
        sc = Script(b"\x00")
        sc.push(hash160(pk.sec()))
        self.assertEqual(sc, p2wpkh(pk))
