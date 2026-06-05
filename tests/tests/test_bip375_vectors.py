"""
Official BIP-375 PSBT test vectors driven through the validator.

Source: https://github.com/macgyver13/bip375-test-generator/

Each valid vector must parse and pass full BIP-375 validation; each invalid
vector must be rejected either at parse time (malformed fields) or by the
validator. The vectors use placeholder UTXO scripts, so the input public key
for SP/DLEQ comes from PSBT_IN_BIP32_DERIVATION (non-taproot) or the output key
in the scriptPubKey (taproot).
"""

import json
import unittest
from pathlib import Path

from embit.base import EmbitError
from embit.silent_payments import SilentPaymentsPSBT, validate_bip375_psbt
from embit.silent_payments.fields import SPValidationError

_VECTORS = Path(__file__).parent / "data" / "bip375_test_vectors.json"


def _load():
    with open(_VECTORS) as f:
        return json.load(f)


class TestBIP375ValidVectors(unittest.TestCase):
    def test_valid_vectors(self):
        data = _load()
        for v in data["valid"]:
            with self.subTest(description=v["description"]):
                psbt = SilentPaymentsPSBT.from_base64(v["psbt"])
                self.assertTrue(validate_bip375_psbt(psbt))


class TestBIP375InvalidVectors(unittest.TestCase):
    def test_invalid_vectors(self):
        data = _load()
        for v in data["invalid"]:
            with self.subTest(description=v["description"]):
                # Rejection may occur at parse time (malformed field lengths) or
                # during validation; both are acceptable failures.
                with self.assertRaises((SPValidationError, EmbitError)):
                    psbt = SilentPaymentsPSBT.from_base64(v["psbt"])
                    validate_bip375_psbt(psbt)


class TestBIP375GlobalProofWithoutShare(unittest.TestCase):
    """A global DLEQ proof present without its matching ECDH share must fail
    cleanly with SPValidationError, not raise an unguarded KeyError."""

    def test_proof_without_share_raises_validation_error(self):
        data = _load()
        for v in data["valid"]:
            psbt = SilentPaymentsPSBT.from_base64(v["psbt"])
            shared = set(psbt.sp_ecdh_shares) & set(psbt.sp_dleq_proofs)
            if not shared:
                continue
            # Drop the global ECDH share but keep the global DLEQ proof.
            scan_key = next(iter(shared))
            del psbt.sp_ecdh_shares[scan_key]
            with self.assertRaisesRegex(
                SPValidationError,
                "PSBT_GLOBAL_SP_DLEQ present without PSBT_GLOBAL_SP_ECDH_SHARE",
            ):
                validate_bip375_psbt(psbt)
            return
        self.skipTest("no vector exercises the global ECDH share path")


if __name__ == "__main__":
    unittest.main()
