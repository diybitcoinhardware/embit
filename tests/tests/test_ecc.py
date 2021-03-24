from binascii import unhexlify, hexlify
from unittest import TestCase
from embit.ec import PublicKey, PrivateKey, Signature, secp256k1
from io import BytesIO


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

    def test_pubkeys(self):
        valid_keys = [
            (
                b"1" * 32,
                True,
                "036930f46dd0b16d866d59d1054aa63298b357499cd1862ef16f3f55f1cafceb82",
            ),
            (
                b"\x00" * 31 + b"\x01",
                False,
                "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            ),
        ]
        pub2 = PublicKey.from_string(
            "026930f46dd0b16d866d59d1054aa63298b357499cd1862ef16f3f55f1cafceb82"
        )
        for secret, compressed, sec in valid_keys:
            priv = PrivateKey(secret, compressed=compressed)
            pub = priv.get_public_key()
            # check str works
            str(priv)
            str(pub)
            self.assertEqual(str(pub), sec)
            self.assertEqual(pub, PublicKey.from_string(sec))
            pub.compressed = not pub.compressed
            self.assertEqual(pub, PublicKey.from_string(sec))
            s = BytesIO()
            self.assertEqual(pub.write_to(s), 33 + 32 * int(not pub.compressed))
            self.assertEqual(priv.write_to(s), 32)
            # round trip
            self.assertEqual(PrivateKey.parse(priv.serialize()), priv)
            self.assertEqual(PublicKey.parse(pub.serialize()), pub)
            # sign random message
            msg = b"5" * 32
            sig = priv.sign(msg)
            self.assertTrue(pub.verify(sig, msg))
            # round trip
            self.assertEqual(Signature.parse(sig.serialize()), sig)
            # checks of the operators
            self.assertEqual(priv < pub, priv.sec() < pub.sec())
            self.assertEqual(priv > pub, priv.sec() > pub.sec())
            self.assertEqual(pub2 < pub, pub2 < priv)
            self.assertEqual(pub2 > pub, pub2 > priv)
            priv == priv
            pub == pub
            self.assertEqual(str(priv), priv.wif())
            self.assertEqual(str(priv), priv.to_base58())
            hash(priv)
            hash(pub)
