import csv
from pathlib import Path
from unittest import TestCase
from binascii import unhexlify

import embit.silent_payments.dleq as dleq
from embit.silent_payments.dleq import DLEQError
from embit.util import py_secp256k1

_DATA_DIR = Path(__file__).parent / "data"
_GENERATE_CSV = _DATA_DIR / "test_vectors_generate_proof.csv"
_VERIFY_CSV = _DATA_DIR / "test_vectors_verify_proof.csv"
_FAKE_INFINITY = b"\x02" + b"\x00" * 32  # x=0 is not on secp256k1

# secp256k1 bindings the dleq module resolves at import time. Rebinding these on
# the module forces the proof code through a specific backend.
_SECP_BINDINGS = (
    "ec_pubkey_create",
    "ec_pubkey_parse",
    "ec_pubkey_serialize",
    "ec_pubkey_tweak_mul",
    "ec_pubkey_combine",
    "EC_COMPRESSED",
)


def _check_generate_vectors(test):
    """Run the official BIP-374 generate-proof vectors against dleq."""
    with open(_GENERATE_CSV, newline="") as fh:
        for row in csv.DictReader(fh):
            idx = row["index"]
            comment = row["comment"]
            result = row["result_proof"]
            with test.subTest(index=idx, comment=comment):
                G_bytes = unhexlify(row["point_G"])
                a_bytes = unhexlify(row["scalar_a"])
                r_bytes = unhexlify(row["auxrand_r"])
                m = unhexlify(row["message"]) if row["message"] else None
                B_hex = row["point_B"]
                B_sec = _FAKE_INFINITY if B_hex == "INFINITY" else unhexlify(B_hex)

                if result == "INVALID":
                    with test.assertRaises(DLEQError):
                        dleq.generate_dleq_proof(
                            a_bytes, B_sec, r=r_bytes, m=m, G=G_bytes
                        )
                else:
                    proof = dleq.generate_dleq_proof(
                        a_bytes, B_sec, r=r_bytes, m=m, G=G_bytes
                    )
                    test.assertEqual(proof, unhexlify(result))


def _check_verify_vectors(test):
    """Run the official BIP-374 verify-proof vectors against dleq."""
    with open(_VERIFY_CSV, newline="") as fh:
        for row in csv.DictReader(fh):
            idx = row["index"]
            comment = row["comment"]
            expected = row["result_success"] == "TRUE"
            with test.subTest(index=idx, comment=comment):
                G_bytes = unhexlify(row["point_G"])
                A_sec = unhexlify(row["point_A"])
                B_sec = unhexlify(row["point_B"])
                C_sec = unhexlify(row["point_C"])
                proof = unhexlify(row["proof"])
                m = unhexlify(row["message"]) if row["message"] else None

                result = dleq.verify_dleq_proof(
                    A_sec, B_sec, C_sec, proof, m=m, G=G_bytes
                )
                test.assertEqual(result, expected)


class TestBIP374GenerateProofVectors(TestCase):
    """Official BIP-374 generate-proof vectors (active backend)."""

    def test_vectors(self):
        _check_generate_vectors(self)


class TestBIP374VerifyProofVectors(TestCase):
    """Official BIP-374 verify-proof vectors (active backend)."""

    def test_vectors(self):
        _check_verify_vectors(self)


class _PurePythonBackendMixin:
    """Force the dleq module onto the pure-Python secp256k1 backend.

    The ctypes backend returns mutable buffers from ec_pubkey_parse, so a missing
    bytearray wrap would still pass there; the pure-Python backend rejects
    immutable bytes. Running the vectors on it guards the MicroPython path.
    """

    def setUp(self):
        super().setUp()
        self._saved_bindings = {
            name: getattr(dleq, name) for name in _SECP_BINDINGS
        }
        for name in _SECP_BINDINGS:
            setattr(dleq, name, getattr(py_secp256k1, name))

    def tearDown(self):
        for name, value in self._saved_bindings.items():
            setattr(dleq, name, value)
        super().tearDown()


class TestBIP374GenerateProofVectorsPurePython(_PurePythonBackendMixin, TestCase):
    """Official BIP-374 generate-proof vectors on the pure-Python backend."""

    def test_vectors(self):
        _check_generate_vectors(self)


class TestBIP374VerifyProofVectorsPurePython(_PurePythonBackendMixin, TestCase):
    """Official BIP-374 verify-proof vectors on the pure-Python backend."""

    def test_vectors(self):
        _check_verify_vectors(self)
