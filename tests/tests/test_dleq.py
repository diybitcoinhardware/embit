import csv
from pathlib import Path
from unittest import TestCase
from binascii import unhexlify

from embit.silent_payments.dleq import generate_dleq_proof, verify_dleq_proof, DLEQError

_DATA_DIR = Path(__file__).parent / "data"
_GENERATE_CSV = _DATA_DIR / "test_vectors_generate_proof.csv"
_VERIFY_CSV = _DATA_DIR / "test_vectors_verify_proof.csv"
_FAKE_INFINITY = b"\x02" + b"\x00" * 32  # x=0 is not on secp256k1


class TestBIP374GenerateProofVectors(TestCase):
    """Official BIP-374 generate-proof test vectors."""

    def test_vectors(self):
        with open(_GENERATE_CSV, newline="") as fh:
            for row in csv.DictReader(fh):
                idx = row["index"]
                G_hex = row["point_G"]
                a_hex = row["scalar_a"]
                B_hex = row["point_B"]
                r_hex = row["auxrand_r"]
                msg_hex = row["message"]
                result = row["result_proof"]
                comment = row["comment"]

                with self.subTest(index=idx, comment=comment):
                    G_bytes = unhexlify(G_hex)

                    a_bytes = unhexlify(a_hex)
                    r_bytes = unhexlify(r_hex)
                    m = unhexlify(msg_hex) if msg_hex else None
                    B_sec = _FAKE_INFINITY if B_hex == "INFINITY" else unhexlify(B_hex)

                    if result == "INVALID":
                        with self.assertRaises(DLEQError):
                            generate_dleq_proof(
                                a_bytes, B_sec, r=r_bytes, m=m, G=G_bytes
                            )
                    else:
                        proof = generate_dleq_proof(
                            a_bytes, B_sec, r=r_bytes, m=m, G=G_bytes
                        )
                        self.assertEqual(proof, unhexlify(result))


class TestBIP374VerifyProofVectors(TestCase):
    """Official BIP-374 verify-proof test vectors."""

    def test_vectors(self):
        with open(_VERIFY_CSV, newline="") as fh:
            for row in csv.DictReader(fh):
                idx = row["index"]
                G_hex = row["point_G"]
                A_hex = row["point_A"]
                B_hex = row["point_B"]
                C_hex = row["point_C"]
                proof_hex = row["proof"]
                msg_hex = row["message"]
                expected = row["result_success"] == "TRUE"
                comment = row["comment"]

                with self.subTest(index=idx, comment=comment):
                    G_bytes = unhexlify(G_hex)

                    A_sec = unhexlify(A_hex)
                    B_sec = unhexlify(B_hex)
                    C_sec = unhexlify(C_hex)
                    proof = unhexlify(proof_hex)
                    m = unhexlify(msg_hex) if msg_hex else None

                    result = verify_dleq_proof(
                        A_sec, B_sec, C_sec, proof, m=m, G=G_bytes
                    )
                    self.assertEqual(result, expected)
