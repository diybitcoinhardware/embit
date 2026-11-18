"""
A witness_utxo must agree with the previous transaction it claims to spend.

Written with unittest, so tests/run_tests.py runs it on MicroPython as well.
The same check is covered for CPython in test_psbt_verification.py, which
needs pytest.
"""

from io import BytesIO
from unittest import TestCase

from embit import ec, script
from embit.psbt import PSBT, PSBTError, CompressMode
from embit.psbtview import PSBTView
from embit.transaction import Transaction, TransactionInput, TransactionOutput

VERSIONS = (None, 2)
COMPRESS_MODES = (
    CompressMode.KEEP_ALL,
    CompressMode.CLEAR_ALL,
    CompressMode.PARTIAL,
)
MISMATCH = "Witness utxo doesn't match non_witness_utxo"


def funded_psbt(version, conflict=None):
    """One p2wpkh input of 10000 sat that pays 9000 sat, so the fee is 1000.

    The input carries the previous transaction and a witness_utxo.
    `conflict` makes the witness_utxo disagree on the amount or the script.
    """
    key = ec.PrivateKey((1).to_bytes(32, "big"))
    spk = script.p2wpkh(key.get_public_key())
    previous = Transaction(
        vin=[TransactionInput(bytes(32), 0)],
        vout=[TransactionOutput(10000, spk)],
    )
    psbt = PSBT(
        Transaction(
            vin=[TransactionInput(previous.txid(), 0)],
            vout=[TransactionOutput(9000, spk)],
        ),
        version=version,
    )
    psbt.inputs[0].non_witness_utxo = previous
    psbt.inputs[0].witness_utxo = TransactionOutput(10000, spk)
    if conflict == "amount":
        psbt.inputs[0].witness_utxo.value = 1000
    elif conflict == "script":
        psbt.inputs[0].witness_utxo.script_pubkey = script.Script(b"\x51")
    return psbt, key


class WitnessUtxoCheckTest(TestCase):
    def assert_refused(self, conflict):
        for version in VERSIONS:
            raw = funded_psbt(version, conflict)[0].serialize()
            for compress in COMPRESS_MODES:
                label = "version %r, compress %r" % (version, compress)
                parsed = PSBT.parse(raw, compress=compress)
                viewed = PSBTView.view(BytesIO(raw), compress=compress).input(0)
                for inp in (parsed.inputs[0], viewed):
                    with self.assertRaises(PSBTError) as ctx:
                        inp.verify()
                    self.assertEqual(str(ctx.exception), MISMATCH, label)
                    self.assertFalse(inp.is_verified, label)
                # the call a signer makes for the whole PSBT
                with self.assertRaises(PSBTError) as ctx:
                    parsed.verify()
                self.assertEqual(str(ctx.exception), MISMATCH, label)
                self.assertFalse(parsed.is_verified, label)

    def test_matching_witness_utxo_verifies_and_signs(self):
        for version in VERSIONS:
            psbt, key = funded_psbt(version)
            raw = psbt.serialize()
            for compress in COMPRESS_MODES:
                label = "version %r, compress %r" % (version, compress)
                parsed = PSBT.parse(raw, compress=compress)
                viewed = PSBTView.view(BytesIO(raw), compress=compress).input(0)
                self.assertTrue(parsed.verify(), label)
                self.assertTrue(viewed.verify(), label)
                self.assertEqual(parsed.fee(), 1000, label)
                self.assertEqual(parsed.sign_with(key), 1, label)
                sig = parsed.inputs[0].partial_sigs[key.get_public_key()]
                self.assertTrue(
                    key.verify(ec.Signature.parse(sig[:-1]), psbt.sighash(0)), label
                )

    def test_witness_utxo_with_forged_amount_is_refused(self):
        self.assert_refused("amount")

    def test_witness_utxo_with_forged_script_is_refused(self):
        self.assert_refused("script")
