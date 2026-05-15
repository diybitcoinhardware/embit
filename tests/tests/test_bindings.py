from binascii import hexlify, unhexlify
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

        # ec_pubkey_tweak_mul mutates in place. The ctypes binding's c_char_p
        # argtype requires `bytes`; the py_secp256k1 implementation requires a
        # mutable `bytearray`. Pass each the type it expects, then compare.
        tweak = b"9" * 32
        pub_py = bytearray(pub1)
        pub_c = ctypes_secp256k1._copy(pub1)  # mutated via the CPython ctypes quirk
        py_secp256k1.ec_pubkey_tweak_mul(pub_py, tweak)
        ctypes_secp256k1.ec_pubkey_tweak_mul(pub_c, tweak)
        self.assertEqual(bytes(pub_py), pub_c)
        pub_c_mutable = bytearray(pub1)
        ctypes_secp256k1.ec_pubkey_tweak_mul(pub_c_mutable, bytearray(tweak))
        self.assertEqual(bytes(pub_py), bytes(pub_c_mutable))

        secret_py = bytearray(secret)
        secret_c = ctypes_secp256k1._copy(secret)
        py_secp256k1.ec_privkey_tweak_mul(secret_py, tweak)
        ctypes_secp256k1.ec_privkey_tweak_mul(secret_c, tweak)
        self.assertEqual(bytes(secret_py), secret_c)
        secret_c_mutable = bytearray(secret)
        ctypes_secp256k1.ec_privkey_tweak_mul(secret_c_mutable, bytearray(tweak))
        self.assertEqual(bytes(secret_py), bytes(secret_c_mutable))

        # ec_pubkey_combine takes varargs and returns a new pubkey.
        pub_other = py_secp256k1.ec_pubkey_create(b"7" * 32)
        self.assertEqual(
            py_secp256k1.ec_pubkey_combine(pub1, pub_other),
            ctypes_secp256k1.ec_pubkey_combine(pub1, pub_other),
        )
        self.assertEqual(
            ctypes_secp256k1.ec_pubkey_combine(pub1, pub_other),
            ctypes_secp256k1.ec_pubkey_combine(bytearray(pub1), bytearray(pub_other)),
        )
        # Three-arg combine.
        pub_third = py_secp256k1.ec_pubkey_create(b"3" * 32)
        self.assertEqual(
            py_secp256k1.ec_pubkey_combine(pub1, pub_other, pub_third),
            ctypes_secp256k1.ec_pubkey_combine(pub1, pub_other, pub_third),
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


# Curve order N. Used to construct overflow/zero tweaks.
_SECP256K1_ORDER = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)


def _tweak_mul_result_x(pubkey_compressed_hex, tweak_hex):
    """Helper: parse a compressed pubkey, multiply by tweak, return x-coord hex."""
    pub = bytearray(py_secp256k1.ec_pubkey_parse(unhexlify(pubkey_compressed_hex)))
    py_secp256k1.ec_pubkey_tweak_mul(pub, unhexlify(tweak_hex))
    return py_secp256k1.ec_pubkey_serialize(bytes(pub))[1:33].hex()


class PrivkeyTweakMulTest(TestCase):
    """Standalone tests for py_secp256k1.ec_privkey_tweak_mul."""

    def test_identity_tweak_one_unchanged(self):
        secret = bytearray(b"2" * 32)
        expected = bytes(secret)
        py_secp256k1.ec_privkey_tweak_mul(secret, (1).to_bytes(32, "big"))
        self.assertEqual(bytes(secret), expected)

    def test_multiplies_scalar_mod_order(self):
        for secret_int, tweak_int in (
            (1, 2),
            (2, 3),
            (12345, 0xDEADBEEF),
            (_SECP256K1_ORDER - 1, _SECP256K1_ORDER - 1),
        ):
            with self.subTest(secret_int=secret_int, tweak_int=tweak_int):
                secret = bytearray(secret_int.to_bytes(32, "big"))
                tweak = tweak_int.to_bytes(32, "big")
                py_secp256k1.ec_privkey_tweak_mul(secret, tweak)
                expected = (secret_int * tweak_int) % _SECP256K1_ORDER
                self.assertEqual(bytes(secret), expected.to_bytes(32, "big"))

    def test_public_key_matches_tweaked_secret(self):
        secret = bytearray(b"5" * 32)
        tweak = b"9" * 32
        pub = bytearray(py_secp256k1.ec_pubkey_create(secret))

        py_secp256k1.ec_privkey_tweak_mul(secret, tweak)
        py_secp256k1.ec_pubkey_tweak_mul(pub, tweak)

        self.assertEqual(bytes(pub), py_secp256k1.ec_pubkey_create(secret))

    def test_rejects_zero_secret(self):
        with self.assertRaises(ValueError):
            py_secp256k1.ec_privkey_tweak_mul(bytearray(32), b"\x01" * 32)

    def test_rejects_zero_tweak(self):
        with self.assertRaises(ValueError):
            py_secp256k1.ec_privkey_tweak_mul(bytearray(b"4" * 32), b"\x00" * 32)

    def test_rejects_overflow_secret_or_tweak(self):
        for secret_int, tweak_int in (
            (_SECP256K1_ORDER, 1),
            (_SECP256K1_ORDER + 1, 1),
            (1, _SECP256K1_ORDER),
            (1, _SECP256K1_ORDER + 1),
            (2**256 - 1, 1),
            (1, 2**256 - 1),
        ):
            with self.subTest(secret_int=secret_int, tweak_int=tweak_int):
                secret = bytearray(secret_int.to_bytes(32, "big"))
                tweak = tweak_int.to_bytes(32, "big")
                with self.assertRaises(ValueError):
                    py_secp256k1.ec_privkey_tweak_mul(secret, tweak)

    def test_rejects_wrong_lengths(self):
        with self.assertRaises(ValueError):
            py_secp256k1.ec_privkey_tweak_mul(bytearray(31), b"\x01" * 32)
        with self.assertRaises(ValueError):
            py_secp256k1.ec_privkey_tweak_mul(bytearray(b"4" * 32), b"\x01" * 31)


class TweakMutationTypeTest(TestCase):
    def test_rejects_immutable_private_key_for_add(self):
        with self.assertRaisesRegex(TypeError, "bytearray"):
            py_secp256k1.ec_privkey_tweak_add(b"2" * 32, b"\x01" * 32)

    def test_rejects_immutable_public_key_for_add(self):
        pub = py_secp256k1.ec_pubkey_create(b"2" * 32)
        with self.assertRaisesRegex(TypeError, "bytearray"):
            py_secp256k1.ec_pubkey_tweak_add(pub, b"\x01" * 32)

    def test_rejects_immutable_private_key_for_mul(self):
        with self.assertRaisesRegex(TypeError, "bytearray"):
            py_secp256k1.ec_privkey_tweak_mul(b"2" * 32, b"\x01" * 32)

    def test_rejects_immutable_public_key_for_mul(self):
        pub = py_secp256k1.ec_pubkey_create(b"2" * 32)
        with self.assertRaisesRegex(TypeError, "bytearray"):
            py_secp256k1.ec_pubkey_tweak_mul(pub, b"\x01" * 32)


class PubkeyTweakMulTest(TestCase):
    """Standalone tests for py_secp256k1.ec_pubkey_tweak_mul.

    Runs without libsecp256k1 — covers correctness via algebraic identities
    and canonical BIP-47 spec vectors.

    Spec reference:
        secp256k1_ec_pubkey_tweak_mul (libsecp256k1 public API)
        https://github.com/bitcoin-core/secp256k1/blob/b11340b3ce2afac1b6ffda4ce5828c30621d2917/include/secp256k1.h#L830-L846

    Tweak validity is defined by secp256k1_ec_seckey_verify (tweak must be a
    32-byte big-endian integer in the range [1, N-1] where N is the curve order):
        https://github.com/bitcoin-core/secp256k1/blob/b11340b3ce2afac1b6ffda4ce5828c30621d2917/include/secp256k1.h#L721-L729
    """

    def test_identity_tweak_one_unchanged(self):
        """tweak_mul(P, 1) == P — multiplicative identity of the scalar group."""
        secret = b"2" * 32
        pub = py_secp256k1.ec_pubkey_create(secret)
        ba = bytearray(pub)
        py_secp256k1.ec_pubkey_tweak_mul(ba, (1).to_bytes(32, "big"))
        self.assertEqual(bytes(ba), pub)

    def test_generator_times_k_equals_pubkey_create_k(self):
        """tweak_mul(G, k) == ec_pubkey_create(k) for valid scalar k.

        ec_pubkey_create(k) is defined as k*G (G = curve generator); so
        tweak_mul applied to G must yield the same point.
        """
        for k in (1, 2, 3, 12345, 0xDEADBEEF, _SECP256K1_ORDER - 1):
            with self.subTest(k=k):
                G = py_secp256k1.ec_pubkey_create((1).to_bytes(32, "big"))
                ba = bytearray(G)
                py_secp256k1.ec_pubkey_tweak_mul(ba, k.to_bytes(32, "big"))
                self.assertEqual(
                    bytes(ba), py_secp256k1.ec_pubkey_create(k.to_bytes(32, "big"))
                )

    def test_double_tweak_composes(self):
        """tweak_mul(tweak_mul(P, a), b) == tweak_mul(P, a*b mod N).

        Associativity of scalar multiplication on the curve.
        """
        secret = b"5" * 32
        P = py_secp256k1.ec_pubkey_create(secret)
        a = int.from_bytes(b"\x03" * 32, "big")
        b = int.from_bytes(b"\x07" * 32, "big")

        # Sequential a then b.
        ba = bytearray(P)
        py_secp256k1.ec_pubkey_tweak_mul(ba, a.to_bytes(32, "big"))
        py_secp256k1.ec_pubkey_tweak_mul(ba, b.to_bytes(32, "big"))

        # Single combined scalar.
        bc = bytearray(P)
        ab = (a * b) % _SECP256K1_ORDER
        py_secp256k1.ec_pubkey_tweak_mul(bc, ab.to_bytes(32, "big"))

        self.assertEqual(bytes(ba), bytes(bc))

    def test_rejects_zero_tweak(self):
        """tweak == 0 must fail: 0*P = point-at-infinity (not a valid pubkey).

        Matches libsecp256k1 behavior: tweak is rejected by seckey_verify, so
        tweak_mul returns 0 (we raise ValueError). See upstream test at
        https://github.com/bitcoin-core/secp256k1/blob/b11340b3ce2afac1b6ffda4ce5828c30621d2917/src/tests.c#L6325
        """
        pub = py_secp256k1.ec_pubkey_create(b"4" * 32)
        ba = bytearray(pub)
        with self.assertRaises(ValueError):
            py_secp256k1.ec_pubkey_tweak_mul(ba, b"\x00" * 32)

    def test_rejects_overflow_tweak(self):
        """tweak >= curve order N must fail (no canonical representative).

        See upstream test at
        https://github.com/bitcoin-core/secp256k1/blob/b11340b3ce2afac1b6ffda4ce5828c30621d2917/src/tests.c#L6357
        """
        pub = py_secp256k1.ec_pubkey_create(b"4" * 32)
        for t in (_SECP256K1_ORDER, _SECP256K1_ORDER + 1, 2**256 - 1):
            with self.subTest(t=t):
                ba = bytearray(pub)
                with self.assertRaises(ValueError):
                    py_secp256k1.ec_pubkey_tweak_mul(ba, t.to_bytes(32, "big"))

    def test_rejects_wrong_pubkey_length(self):
        with self.assertRaises(ValueError):
            py_secp256k1.ec_pubkey_tweak_mul(bytearray(63), b"\x01" * 32)

    def test_rejects_wrong_tweak_length(self):
        pub = py_secp256k1.ec_pubkey_create(b"4" * 32)
        with self.assertRaises(ValueError):
            py_secp256k1.ec_pubkey_tweak_mul(bytearray(pub), b"\x01" * 31)

    def test_bip47_spec_vectors(self):
        """Canonical BIP-47 ECDH vectors: x-coord of (Alice's a0 * Bob's Bi).

        BIP-47 (Reusable Payment Codes) defines the shared secret as a*B where
        a is the payer's private key and B is the recipient's derived pubkey.
        These vectors are the X coordinate of that curve point — exactly what
        ec_pubkey_tweak_mul computes.

        Spec: https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki
        Test vectors: https://gist.github.com/SamouraiDev/6aad669604c5930864bd
        """
        a0 = unhexlify(
            "8d6a8ecd8ee5e0042ad0cb56e3a971c760b5145c3917a8e7beaf0ed92d7a520c"
        )
        vectors = [
            (
                "024ce8e3b04ea205ff49f529950616c3db615b1e37753858cc60c1ce64d17e2ad8",
                "f5bb84706ee366052471e6139e6a9a969d586e5fe6471a9b96c3d8caefe86fef",
            ),
            (
                "03e092e58581cf950ff9c8fc64395471733e13f97dedac0044ebd7d60ccc1eea4d",
                "adfb9b18ee1c4460852806a8780802096d67a8c1766222598dc801076beb0b4d",
            ),
            (
                "029b5f290ef2f98a0462ec691f5cc3ae939325f7577fcaf06cfc3b8fc249402156",
                "79e860c3eb885723bb5a1d54e5cecb7df5dc33b1d56802906762622fa3c18ee5",
            ),
            (
                "02094be7e0eef614056dd7c8958ffa7c6628c1dab6706f2f9f45b5cbd14811de44",
                "d8339a01189872988ed4bd5954518485edebf52762bf698b75800ac38e32816d",
            ),
            (
                "031054b95b9bc5d2a62a79a58ecfe3af000595963ddc419c26dab75ee62e613842",
                "14c687bc1a01eb31e867e529fee73dd7540c51b9ff98f763adf1fc2f43f98e83",
            ),
            (
                "03dac6d8f74cacc7630106a1cfd68026c095d3d572f3ea088d9a078958f8593572",
                "725a8e3e4f74a50ee901af6444fb035cb8841e0f022da2201b65bc138c6066a2",
            ),
            (
                "02396351f38e5e46d9a270ad8ee221f250eb35a575e98805e94d11f45d763c4651",
                "521bf140ed6fb5f1493a5164aafbd36d8a9e67696e7feb306611634f53aa9d1f",
            ),
            (
                "039d46e873827767565141574aecde8fb3b0b4250db9668c73ac742f8b72bca0d0",
                "5f5ecc738095a6fb1ea47acda4996f1206d3b30448f233ef6ed27baf77e81e46",
            ),
            (
                "038921acc0665fd4717eb87f81404b96f8cba66761c847ebea086703a6ae7b05bd",
                "1e794128ac4c9837d7c3696bbc169a8ace40567dc262974206fcf581d56defb4",
            ),
            (
                "03d51a06c6b48f067ff144d5acdfbe046efa2e83515012cf4990a89341c1440289",
                "fe36c27c62c99605d6cd7b63bf8d9fe85d753592b14744efca8be20a4d767c37",
            ),
        ]
        for i, (B_hex, expected_x_hex) in enumerate(vectors):
            with self.subTest(i=i):
                self.assertEqual(
                    _tweak_mul_result_x(B_hex, a0.hex()), expected_x_hex
                )


class PubkeyCombineTest(TestCase):
    """Standalone tests for py_secp256k1.ec_pubkey_combine.

    Spec reference:
        secp256k1_ec_pubkey_combine (libsecp256k1 public API)
        https://github.com/bitcoin-core/secp256k1/blob/b11340b3ce2afac1b6ffda4ce5828c30621d2917/include/secp256k1.h#L884-L898
    """

    def test_combine_single_pubkey_unchanged(self):
        """combine(P) == P — combining one pubkey is a no-op."""
        pub = py_secp256k1.ec_pubkey_create(b"4" * 32)
        self.assertEqual(py_secp256k1.ec_pubkey_combine(pub), pub)

    def test_combine_p_plus_p_equals_tweak_mul_by_two(self):
        """combine(P, P) == tweak_mul(P, 2) — point doubling.

        P + P on the curve equals 2*P. Mirrors the 'Tweak mul * 2 = 1+1'
        identity in bitcoin-core/secp256k1's test suite:
        https://github.com/bitcoin-core/secp256k1/blob/b11340b3ce2afac1b6ffda4ce5828c30621d2917/src/tests.c#L6383-L6386
        """
        P = py_secp256k1.ec_pubkey_create(b"9" * 32)
        combined = py_secp256k1.ec_pubkey_combine(P, P)
        doubled = bytearray(P)
        py_secp256k1.ec_pubkey_tweak_mul(doubled, (2).to_bytes(32, "big"))
        self.assertEqual(combined, bytes(doubled))

    def test_combine_three_pubkeys_associates(self):
        """combine(A, B, C) == combine(combine(A, B), C).

        Point addition on an elliptic curve is associative.
        """
        A = py_secp256k1.ec_pubkey_create(b"1" * 32)
        B = py_secp256k1.ec_pubkey_create(b"2" * 32)
        C = py_secp256k1.ec_pubkey_create(b"3" * 32)
        self.assertEqual(
            py_secp256k1.ec_pubkey_combine(A, B, C),
            py_secp256k1.ec_pubkey_combine(
                py_secp256k1.ec_pubkey_combine(A, B), C
            ),
        )

    def test_combine_rejects_pubkey_and_negation(self):
        """combine(P, -P) sums to the point at infinity — must fail.

        Per the libsecp256k1 API contract, 'the sum of the public keys is not
        valid' returns 0 (we raise ValueError). The point at infinity is not a
        valid pubkey representation.
        """
        P = py_secp256k1.ec_pubkey_create(b"5" * 32)
        neg_P = py_secp256k1.ec_pubkey_negate(P)
        with self.assertRaises(ValueError):
            py_secp256k1.ec_pubkey_combine(P, neg_P)

    def test_combine_rejects_no_args(self):
        """API contract: n must be at least 1 (see header doc above)."""
        with self.assertRaises(ValueError):
            py_secp256k1.ec_pubkey_combine()

    def test_combine_rejects_wrong_length(self):
        pub = py_secp256k1.ec_pubkey_create(b"6" * 32)
        with self.assertRaises(ValueError):
            py_secp256k1.ec_pubkey_combine(pub, b"\x00" * 63)
