from binascii import unhexlify, hexlify
from unittest import TestCase
from embit.util import secp256k1


class SECPTest(TestCase):
    def test_identity(self):
        """ 1 * G """
        answer = b"0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        one = 1
        bone = one.to_bytes(32, "big")
        g = secp256k1.ec_pubkey_create(bone)
        der = secp256k1.ec_pubkey_serialize(g, secp256k1.EC_UNCOMPRESSED)
        g_hex = hexlify(der)
        self.assertEqual(answer, g_hex)
