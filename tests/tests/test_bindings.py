from binascii import hexlify
from unittest import TestCase, skipUnless
from embit.util import py_secp256k1

try:
    from embit.util import ctypes_secp256k1
except Exception:  # pragma: no cover - environment dependent
    ctypes_secp256k1 = None
    print(
        "[tests] libsecp256k1 ctypes backend unavailable; "
        "skipping ctypes parity tests and using pure-Python fallback."
    )
    _CTYPES_AVAILABLE = False
else:
    _CTYPES_AVAILABLE = True
    _CTYPES_SECP = getattr(ctypes_secp256k1, "_secp", None)


def _ctypes_has_symbol(name):
    if not _CTYPES_AVAILABLE or _CTYPES_SECP is None:
        return False
    try:
        getattr(_CTYPES_SECP, name)
        return True
    except AttributeError:
        return False


_RECOVERY_AVAILABLE = all(
    _ctypes_has_symbol(symbol)
    for symbol in (
        "secp256k1_ecdsa_sign_recoverable",
        "secp256k1_ecdsa_recoverable_signature_parse_compact",
        "secp256k1_ecdsa_recoverable_signature_serialize_compact",
        "secp256k1_ecdsa_recoverable_signature_convert",
        "secp256k1_ecdsa_recover",
    )
)
_SCHNORR_AVAILABLE = all(
    _ctypes_has_symbol(symbol)
    for symbol in (
        "secp256k1_xonly_pubkey_from_pubkey",
        "secp256k1_schnorrsig_verify",
        "secp256k1_schnorrsig_sign",
        "secp256k1_keypair_create",
    )
)


@skipUnless(
    _CTYPES_AVAILABLE,
    "libsecp256k1 ctypes backend unavailable; pure-Python fallback in use",
)
class BindingsTest(TestCase):
    def test_identity(self):
        """1 * G"""
        for secp256k1 in [py_secp256k1, ctypes_secp256k1]:
            answer = (
                b"0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179"
                b"8483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
            )
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

        # check that extra data is handled in the same way
        sig = ctypes_secp256k1.ecdsa_sign(msg, secret, None, b"1" * 32)
        self.assertEqual(sig, py_secp256k1.ecdsa_sign(msg, secret, None, b"1" * 32))

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

    @skipUnless(
        _SCHNORR_AVAILABLE,
        "ctypes backend missing schnorr symbols; skipping parity checks",
    )
    def test_schnorr(self):
        for i in range(1, 10):
            secret = bytes([i] * 32)
            pub1 = ctypes_secp256k1.ec_pubkey_create(secret)
            pub2 = py_secp256k1.ec_pubkey_create(secret)
            self.assertEqual(pub1, pub2)
            pub1, par = ctypes_secp256k1.xonly_pubkey_from_pubkey(pub1)
            pub2, par = py_secp256k1.xonly_pubkey_from_pubkey(pub2)
            self.assertEqual(pub1, pub2)
            msg = b"q" * 32

            # without aux data
            sig1 = ctypes_secp256k1.schnorrsig_sign(msg, secret)
            sig2 = py_secp256k1.schnorrsig_sign(msg, secret)
            self.assertEqual(sig1, sig2)

            # with aux data
            sig1 = ctypes_secp256k1.schnorrsig_sign(msg, secret, None, b"4" * 32)
            sig2 = py_secp256k1.schnorrsig_sign(msg, secret, None, b"4" * 32)
            self.assertEqual(sig1, sig2)

            self.assertTrue(ctypes_secp256k1.schnorrsig_verify(sig1, msg, pub1))
            self.assertTrue(py_secp256k1.schnorrsig_verify(sig2, msg, pub2))
            self.assertTrue(ctypes_secp256k1.schnorrsig_verify(sig2, msg, pub1))
            self.assertTrue(py_secp256k1.schnorrsig_verify(sig1, msg, pub2))

            self.assertFalse(ctypes_secp256k1.schnorrsig_verify(sig1, b"w" * 32, pub1))
            self.assertFalse(py_secp256k1.schnorrsig_verify(sig2, b"w" * 32, pub2))
            self.assertFalse(ctypes_secp256k1.schnorrsig_verify(sig2, b"w" * 32, pub1))
            self.assertFalse(py_secp256k1.schnorrsig_verify(sig1, b"w" * 32, pub2))

            self.assertEqual(
                ctypes_secp256k1.keypair_create(secret),
                py_secp256k1.keypair_create(secret),
            )

    @skipUnless(
        _RECOVERY_AVAILABLE,
        "ctypes backend missing recovery symbols; skipping parity checks",
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
