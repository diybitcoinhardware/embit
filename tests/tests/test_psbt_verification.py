"""
How verify() and InputScope.update() keep the utxo data of an input honest.

Written with unittest, so tests/run_tests.py runs it on MicroPython as well.
The witness_utxo against non_witness_utxo check itself is in
test_psbt_witness_utxo.py.
"""

from io import BytesIO
from unittest import TestCase

from embit import ec, script
from embit.psbt import PSBT, PSBTError, CompressMode, InputScope
from embit.psbtview import PSBTView
from embit.transaction import (
    SIGHASH,
    Transaction,
    TransactionInput,
    TransactionOutput,
)

VERSIONS = (None, 2)
COMPRESS_MODES = (
    CompressMode.KEEP_ALL,
    CompressMode.CLEAR_ALL,
    CompressMode.PARTIAL,
)
# the modes that keep only a hash of the previous transaction
CACHE_MODES = (CompressMode.CLEAR_ALL, CompressMode.PARTIAL)


def funded_psbt(version):
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
    return psbt, key


def two_output_psbt(version):
    psbt, key = funded_psbt(version)
    spk = script.p2pkh(key.get_public_key())
    previous = psbt.inputs[0].non_witness_utxo
    previous.vout = [TransactionOutput(10000, spk), TransactionOutput(1000000, spk)]
    psbt.inputs[0].txid = previous.txid()
    psbt.inputs[0].witness_utxo = None
    return psbt, key


class PSBTVerificationTest(TestCase):
    def assert_refused(self, text, func, label=""):
        try:
            func()
        except PSBTError as e:
            self.assertIn(text, str(e), label)
            return
        self.fail("PSBTError not raised: %s" % label)

    def test_view_signs_the_taproot_amounts_it_shows(self):
        key = ec.PrivateKey((1).to_bytes(32, "big"))
        spk = script.p2tr(key.get_public_key())
        previous = Transaction(
            vin=[TransactionInput(bytes(32), 0)],
            vout=[TransactionOutput(10000, spk)],
        )
        for version in VERSIONS:
            psbt = PSBT(
                Transaction(
                    vin=[TransactionInput(previous.txid(), 0)],
                    vout=[TransactionOutput(9000, spk)],
                ),
                version=version,
            )
            psbt.inputs[0].non_witness_utxo = previous
            # unverified witness utxo understating the amount
            psbt.inputs[0].witness_utxo = TransactionOutput(1000, spk)
            raw = psbt.serialize()
            for compress in COMPRESS_MODES:
                label = "version %r, compress %r" % (version, compress)
                view = PSBTView.view(BytesIO(raw), compress=compress)
                shown = view.input(0).utxo
                expected = psbt.tx.sighash_taproot(
                    0, [shown.script_pubkey], [shown.value], sighash=SIGHASH.DEFAULT
                )
                self.assertEqual(
                    view.sighash(0, sighash=SIGHASH.DEFAULT), expected, label
                )
                parsed = PSBT.parse(raw, compress=compress)
                self.assertEqual(
                    parsed.sighash(0, sighash=SIGHASH.DEFAULT), expected, label
                )

    def test_refusal_clears_an_earlier_verification(self):
        for version in VERSIONS:
            inp = funded_psbt(version)[0].inputs[0]
            self.assertTrue(inp.verify())
            self.assertTrue(inp.is_verified)
            inp.witness_utxo = TransactionOutput(1000, inp.witness_utxo.script_pubkey)
            with self.assertRaises(PSBTError):
                inp.verify()
            self.assertFalse(inp.is_verified)

    def test_verify_rejects_invalid_non_witness_output_index(self):
        for index in (-1, 1, None):
            label = "index %r" % index
            psbt, _ = funded_psbt(None)
            psbt.inputs[0].vout = index
            self.assert_refused("output index", psbt.verify, label)
            self.assertFalse(psbt.is_verified, label)

    def test_update_with_utxo_data_clears_verified_state(self):
        psbt, _ = funded_psbt(None)
        inp = psbt.inputs[0]
        inp.witness_utxo = None
        self.assertTrue(psbt.verify())
        # merging signatures keeps the verification
        other = InputScope()
        other.partial_sigs[b"pub"] = b"sig"
        inp.update(other)
        self.assertTrue(inp.is_verified)
        other = InputScope()
        other.witness_utxo = TransactionOutput(1000000, inp.utxo.script_pubkey)
        inp.update(other)
        self.assertFalse(inp.is_verified)
        self.assert_refused("Witness utxo doesn't match", psbt.verify)

    def test_update_keeps_compressed_utxo_with_its_txhash(self):
        for compress in CACHE_MODES:
            label = "compress %r" % compress
            psbt, _ = funded_psbt(None)
            psbt.inputs[0].witness_utxo = None
            spk = psbt.inputs[0].non_witness_utxo.vout[0].script_pubkey
            good = PSBT.parse(psbt.serialize(), compress=compress)
            self.assertTrue(good.verify(), label)
            # unrelated previous transaction with an inflated amount
            psbt.inputs[0].non_witness_utxo = Transaction(
                vin=[TransactionInput(b"\x07" * 32, 0)],
                vout=[TransactionOutput(1000000, spk)],
            )
            evil = PSBT.parse(psbt.serialize(), compress=compress)
            good.inputs[0].update(evil.inputs[0])
            self.assertFalse(good.is_verified, label)
            self.assert_refused("txid doesn't match", good.verify, label)
            self.assertFalse(good.is_verified, label)

    def test_update_output_index_cannot_reuse_cached_amount(self):
        for version in VERSIONS:
            for compress in CACHE_MODES:
                for replacement in (None, "full", "compressed"):
                    self.check_output_index_update(version, compress, replacement)

    def check_output_index_update(self, version, compress, replacement):
        label = "version %r, compress %r, replacement %r" % (
            version,
            compress,
            replacement,
        )
        original, key = two_output_psbt(version)
        previous = original.inputs[0].non_witness_utxo
        psbt = PSBT.parse(original.serialize(), compress=compress)
        self.assertTrue(psbt.verify(), label)
        self.assertEqual(psbt.fee(), 1000, label)
        other = InputScope()
        other.vout = 1
        if replacement == "full":
            other.non_witness_utxo = previous
        elif replacement == "compressed":
            original.inputs[0].vout = 1
            other = PSBT.parse(original.serialize(), compress=compress).inputs[0]
        psbt.inputs[0].update(other)
        self.assertFalse(psbt.is_verified, label)
        if replacement is None:
            self.assert_refused("Missing non_witness_utxo", psbt.verify, label)
            self.assertFalse(psbt.is_verified, label)
            self.assertIsNone(psbt.inputs[0].utxo, label)
            self.assert_refused(
                "Missing previous utxo", lambda: psbt.sign_with(key), label
            )
            # Supplying the full previous transaction recovers the correct output.
            other.non_witness_utxo = previous
            psbt.inputs[0].update(other)
        self.assertTrue(psbt.verify(), label)
        self.assertEqual(psbt.inputs[0].utxo.value, 1000000, label)
        self.assertEqual(psbt.fee(), 991000, label)
        self.assertEqual(psbt.sign_with(key), 1, label)
        actual = PSBT(psbt.tx)
        actual.inputs[0].non_witness_utxo = previous
        signature = psbt.inputs[0].partial_sigs[key.get_public_key()]
        self.assertTrue(
            key.verify(ec.Signature.parse(signature[:-1]), actual.sighash(0)), label
        )

    def test_update_unchanged_prevout_keeps_usable_cache(self):
        for version in VERSIONS:
            for compress in CACHE_MODES:
                label = "version %r, compress %r" % (version, compress)
                original, _ = two_output_psbt(version)
                psbt = PSBT.parse(original.serialize(), compress=compress)
                self.assertTrue(psbt.verify(), label)
                psbt.inputs[0].update(InputScope(vin=psbt.inputs[0].vin))
                self.assertFalse(psbt.is_verified, label)
                self.assertTrue(psbt.verify(), label)
                self.assertEqual(psbt.fee(), 1000, label)

    def test_update_rejects_incoming_cache_with_changed_index(self):
        for version in VERSIONS:
            for compress in CACHE_MODES:
                label = "version %r, compress %r" % (version, compress)
                original, _ = two_output_psbt(version)
                incoming = PSBT.parse(original.serialize(), compress=compress).inputs[0]
                incoming.vout = 1
                original.inputs[0].update(incoming)
                self.assert_refused(
                    "Cached utxo doesn't match output index", original.verify, label
                )
                self.assertFalse(original.is_verified, label)

    def test_update_full_transaction_replaces_old_cached_hash(self):
        for compress in CACHE_MODES:
            label = "compress %r" % compress
            original, _ = two_output_psbt(None)
            psbt = PSBT.parse(original.serialize(), compress=compress)
            self.assertTrue(psbt.verify(), label)
            previous = original.inputs[0].non_witness_utxo
            previous.vout[0].value = 20000
            original.inputs[0].txid = previous.txid()
            psbt.inputs[0].update(original.inputs[0])
            self.assertFalse(psbt.is_verified, label)
            self.assertTrue(psbt.verify(), label)
            self.assertEqual(psbt.fee(), 11000, label)

    def test_update_full_transaction_is_not_shadowed_by_cache(self):
        for compress in CACHE_MODES:
            label = "compress %r" % compress
            original, _ = two_output_psbt(None)
            psbt = PSBT.parse(original.serialize(), compress=compress)
            self.assertTrue(psbt.verify(), label)
            other = InputScope()
            other.non_witness_utxo = Transaction(
                vin=[TransactionInput(b"\x07" * 32, 0)],
                vout=[TransactionOutput(5, original.inputs[0].utxo.script_pubkey)],
            )
            psbt.inputs[0].update(other)
            self.assert_refused("txid doesn't match", psbt.verify, label)
            self.assertFalse(psbt.is_verified, label)

    def test_update_from_compressed_scope_drops_other_full_transaction(self):
        for compress in CACHE_MODES:
            for witness_utxo in (False, True):
                label = "compress %r, witness_utxo %r" % (compress, witness_utxo)
                psbt, _ = funded_psbt(None)
                psbt.inputs[0].witness_utxo = None
                stale = psbt.inputs[0].non_witness_utxo
                spk = stale.vout[0].script_pubkey
                # the input moved to an output of a different previous transaction
                previous = Transaction(
                    vin=[TransactionInput(b"\x07" * 32, 0)],
                    vout=[TransactionOutput(20000, spk)],
                )
                replacement = PSBT(
                    Transaction(
                        vin=[TransactionInput(previous.txid(), 0)], vout=psbt.tx.vout
                    )
                )
                replacement.inputs[0].non_witness_utxo = previous
                if witness_utxo:
                    replacement.inputs[0].witness_utxo = previous.vout[0]
                incoming = PSBT.parse(
                    replacement.serialize(), compress=compress
                ).inputs[0]
                self.assertIsNone(incoming.non_witness_utxo, label)
                psbt.inputs[0].update(incoming)
                self.assertTrue(psbt.verify(), label)
                self.assertEqual(psbt.fee(), 11000, label)
                # the transaction the cache was not streamed from is not written back
                self.assertIsNone(psbt.inputs[0].non_witness_utxo, label)
                reparsed = PSBT.parse(psbt.serialize())
                self.assertEqual(reparsed.inputs[0].txid, previous.txid(), label)
                self.assertIsNone(reparsed.inputs[0].non_witness_utxo, label)
                self.assertFalse(reparsed.verify(ignore_missing=True), label)

    def test_update_from_compressed_scope_keeps_its_full_transaction(self):
        for compress in CACHE_MODES:
            label = "compress %r" % compress
            psbt, _ = funded_psbt(None)
            previous = psbt.inputs[0].non_witness_utxo
            incoming = PSBT.parse(psbt.serialize(), compress=compress).inputs[0]
            psbt.inputs[0].update(incoming)
            self.assertIs(psbt.inputs[0].non_witness_utxo, previous, label)
            self.assertTrue(psbt.verify(), label)
            self.assertTrue(PSBT.parse(psbt.serialize()).verify(), label)
