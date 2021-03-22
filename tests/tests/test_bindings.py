from binascii import unhexlify, hexlify
from unittest import TestCase
from embit.util import py_secp256k1
from embit.util import ctypes_secp256k1


class BindingsTest(TestCase):
    def test_identity(self):
        """ 1 * G """
        for secp256k1 in [py_secp256k1, ctypes_secp256k1]:
            answer = b"0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
            one = 1
            bone = one.to_bytes(32, "big")
            g = secp256k1.ec_pubkey_create(bone)
            der = secp256k1.ec_pubkey_serialize(g, secp256k1.EC_UNCOMPRESSED)
            g_hex = hexlify(der)
            self.assertEqual(answer, g_hex)

    def test_cross(self):
        secret = b"5" * 32
        pub1 = ctypes_secp256k1.ec_pubkey_create(secret)
        pub2 = py_secp256k1.ec_pubkey_create(secret)
        self.assertEqual(pub1, pub2)
        der = ctypes_secp256k1.ec_pubkey_serialize(pub1)
        self.assertEqual(der, py_secp256k1.ec_pubkey_serialize(pub1))
        self.assertEqual(
            ctypes_secp256k1.ec_pubkey_parse(der), py_secp256k1.ec_pubkey_parse(der)
        )

        msg = b"7" * 32
        sig = ctypes_secp256k1.ecdsa_sign(msg, secret)
        self.assertEqual(sig, py_secp256k1.ecdsa_sign(msg, secret))
        compact = py_secp256k1.ecdsa_signature_serialize_compact(sig)
        der = py_secp256k1.ecdsa_signature_serialize_der(sig)
        self.assertEqual(
            compact, ctypes_secp256k1.ecdsa_signature_serialize_compact(sig)
        )
        self.assertEqual(der, ctypes_secp256k1.ecdsa_signature_serialize_der(sig))

        self.assertEqual(sig, ctypes_secp256k1.ecdsa_signature_parse_compact(compact))
        self.assertEqual(sig, py_secp256k1.ecdsa_signature_parse_compact(compact))
        self.assertEqual(sig, ctypes_secp256k1.ecdsa_signature_parse_der(der))
        self.assertEqual(sig, py_secp256k1.ecdsa_signature_parse_der(der))

        self.assertEqual(py_secp256k1.ecdsa_verify(sig, msg, pub1), True)
        self.assertEqual(ctypes_secp256k1.ecdsa_verify(sig, msg, pub1), True)

        self.assertEqual(py_secp256k1.ecdsa_verify(sig, b"a" * 32, pub1), False)
        self.assertEqual(ctypes_secp256k1.ecdsa_verify(sig, b"a" * 32, pub1), False)

        self.assertEqual(
            py_secp256k1.ec_privkey_add(secret, b"9" * 32),
            ctypes_secp256k1.ec_privkey_add(secret, b"9" * 32),
        )

        self.assertEqual(
            py_secp256k1.ec_pubkey_add(pub1, b"9" * 32),
            ctypes_secp256k1.ec_pubkey_add(pub1, b"9" * 32),
        )

    def test_recovery(self):
        secret = b"1" * 32
        msg = b"2" * 32
        sig = ctypes_secp256k1.ecdsa_sign_recoverable(msg, secret)
        sig2 = py_secp256k1.ecdsa_sign_recoverable(msg, secret)
        self.assertEqual(sig, sig2)

        # signature (r,s) = (4,4), which can be recovered with all 4 recids.
        sig = (b"\x04" + b"\x00" * 31) * 2
        for i in range(4):
            pub = ctypes_secp256k1.ecdsa_recover(sig + bytes([i]), msg)
            pub2 = py_secp256k1.ecdsa_recover(sig + bytes([i]), msg)
            self.assertEqual(pub, pub2)
