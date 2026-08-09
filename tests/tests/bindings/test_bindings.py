from binascii import hexlify
from unittest import TestCase, skipUnless
from embit.util import ctypes_secp256k1, secp256k1

# Schnorr and ECDSA recovery are optional modules in both upstream secp256k1
# and zkp. If a future build of embit targets a libsecp256k1 without these
# modules enabled, these checks let the test suite skip cleanly instead of
# erroring out.
#
# Capability is checked against the `embit.util.secp256k1` selector module
# (imported as `secp256k1` above) rather than against `ctypes_secp256k1`
# directly. The selector imports ctypes_secp256k1 and then walks an
# `_OPTIONAL_SYMBOLS` table, pruning names whose underlying C symbols
# weren't present in the loaded library. So `hasattr(secp256k1, name)` is
# the source of truth for "is this capability available?" --
# `hasattr(ctypes_secp256k1, name)` would always return True because the
# ctypes-binding Python functions are defined unconditionally regardless
# of which C symbols actually exist in libsecp256k1.
_SCHNORR_AVAILABLE = all(
    hasattr(secp256k1, name)
    for name in (
        "xonly_pubkey_from_pubkey",
        "schnorrsig_sign",
        "schnorrsig_verify",
        "keypair_create",
    )
)
_RECOVERY_AVAILABLE = all(
    hasattr(secp256k1, name)
    for name in (
        "ecdsa_sign_recoverable",
        "ecdsa_recoverable_signature_serialize_compact",
        "ecdsa_recoverable_signature_parse_compact",
        "ecdsa_recoverable_signature_convert",
        "ecdsa_recover",
    )
)


class BindingsTest(TestCase):
    def test_identity(self):
        """1 * G"""
        answer = (
            b"0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179"
            b"8483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        )
        one = 1
        bone = one.to_bytes(32, "big")
        g = ctypes_secp256k1.ec_pubkey_create(bone)
        der = ctypes_secp256k1.ec_pubkey_serialize(g, ctypes_secp256k1.EC_UNCOMPRESSED)
        g_hex = hexlify(der)
        self.assertEqual(answer, g_hex)

    def test_cross(self):
        secret = b"5" * 32
        pub1 = ctypes_secp256k1.ec_pubkey_create(secret)
        der = ctypes_secp256k1.ec_pubkey_serialize(pub1)
        self.assertEqual(pub1, ctypes_secp256k1.ec_pubkey_parse(der))

        msg = b"7" * 32
        sig = ctypes_secp256k1.ecdsa_sign(msg, secret)

        # extra data is accepted
        sig_extra = ctypes_secp256k1.ecdsa_sign(msg, secret, None, b"1" * 32)

        compact = ctypes_secp256k1.ecdsa_signature_serialize_compact(sig)
        der = ctypes_secp256k1.ecdsa_signature_serialize_der(sig)
        self.assertEqual(sig, ctypes_secp256k1.ecdsa_signature_parse_compact(compact))
        self.assertEqual(sig, ctypes_secp256k1.ecdsa_signature_parse_der(der))

        # The extra-data variant must also survive the same serialize/parse
        # roundtrips so a regression in the aux-data signing path can't sneak
        # past as a "we verified, that's enough" pass.
        compact_extra = ctypes_secp256k1.ecdsa_signature_serialize_compact(sig_extra)
        der_extra = ctypes_secp256k1.ecdsa_signature_serialize_der(sig_extra)
        self.assertEqual(
            sig_extra,
            ctypes_secp256k1.ecdsa_signature_parse_compact(compact_extra),
        )
        self.assertEqual(
            sig_extra,
            ctypes_secp256k1.ecdsa_signature_parse_der(der_extra),
        )

        self.assertEqual(ctypes_secp256k1.ecdsa_verify(sig, msg, pub1), True)
        self.assertEqual(ctypes_secp256k1.ecdsa_verify(sig_extra, msg, pub1), True)
        self.assertEqual(ctypes_secp256k1.ecdsa_verify(sig, b"a" * 32, pub1), False)

        # tweak via privkey and via pubkey reach the same point
        tweak = b"9" * 32
        tweaked_priv = ctypes_secp256k1.ec_privkey_add(secret, tweak)
        self.assertEqual(
            ctypes_secp256k1.ec_pubkey_create(tweaked_priv),
            ctypes_secp256k1.ec_pubkey_add(pub1, tweak),
        )

    @skipUnless(
        _SCHNORR_AVAILABLE,
        "secp256k1 build is missing the Schnorr module",
    )
    def test_schnorr(self):
        for i in range(1, 10):
            secret = bytes([i] * 32)
            pub1 = ctypes_secp256k1.ec_pubkey_create(secret)
            pub1, par = ctypes_secp256k1.xonly_pubkey_from_pubkey(pub1)
            msg = b"q" * 32

            # without aux data
            sig_no_aux = ctypes_secp256k1.schnorrsig_sign(msg, secret)

            # with aux data
            sig_with_aux = ctypes_secp256k1.schnorrsig_sign(msg, secret, None, b"4" * 32)

            self.assertTrue(ctypes_secp256k1.schnorrsig_verify(sig_no_aux, msg, pub1))
            self.assertTrue(ctypes_secp256k1.schnorrsig_verify(sig_with_aux, msg, pub1))

            self.assertFalse(ctypes_secp256k1.schnorrsig_verify(sig_no_aux, b"w" * 32, pub1))
            self.assertFalse(ctypes_secp256k1.schnorrsig_verify(sig_with_aux, b"w" * 32, pub1))

            # libsecp's keypair structure is a 96-byte opaque blob (32-byte
            # secret + 64-byte uncompressed pubkey). Assert the length so a
            # binding-level shape regression fails here rather than at a
            # downstream consumer.
            keypair = ctypes_secp256k1.keypair_create(secret)
            self.assertEqual(len(keypair), 96)

    @skipUnless(
        _RECOVERY_AVAILABLE,
        "secp256k1 build is missing the ECDSA recovery module",
    )
    def test_recovery(self):
        secret = b"1" * 32
        msg = b"2" * 32
        sig = ctypes_secp256k1.ecdsa_sign_recoverable(msg, secret)
        self.assertEqual(len(sig), 65)

        # sign/recover roundtrip: the recovered pubkey matches the secret's pubkey
        expected_pub = ctypes_secp256k1.ec_pubkey_create(secret)
        self.assertEqual(ctypes_secp256k1.ecdsa_recover(sig, msg), expected_pub)


class WrapperImportTest(TestCase):
    """End-to-end coverage of the selector module's fail-fast behavior.

    These tests live separately from BindingsTest because they don't exercise
    the libsecp256k1 bindings -- they exercise what `embit.util.secp256k1`
    does when those bindings cannot be loaded. They run in a subprocess so
    we get a clean import state (once `embit.util.secp256k1` has been
    imported successfully by other tests in the suite, it can't be reliably
    unloaded and re-loaded in-process). The subprocess script lives next
    to this file as `_helper_libsecp_load_failure.py`.
    """

    def test_libsecp_load_failure_raises_with_chained_cause(self):
        """Verifies the contract that future maintenance can't silently break:
        when the underlying ctypes module fails at import time, the selector
        raises Libsecp256k1NotAvailable with the original error chained as
        __cause__. Catches regressions like dropping the `from _cp_exc`
        clause or widening the `except ImportError:` to a bare `except:`.
        """
        import os
        import subprocess
        import sys

        helper = os.path.join(
            os.path.dirname(__file__), "_helper_libsecp_load_failure.py"
        )
        result = subprocess.run(
            [sys.executable, helper], capture_output=True, text=True
        )

        self.assertEqual(
            result.returncode,
            0,
            "subprocess did not raise on the wrapper import; "
            "stdout={!r} stderr={!r}".format(result.stdout, result.stderr),
        )
        lines = result.stdout.strip().split("\n")
        self.assertEqual(lines[0], "embit.util.secp256k1.Libsecp256k1NotAvailable")
        self.assertEqual(lines[1], "RuntimeError")
        self.assertEqual(lines[2], "simulated libsecp loader failure")
