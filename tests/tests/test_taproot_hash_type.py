from io import BytesIO
from unittest import TestCase

from embit import ec
from embit.psbt import PSBT
from embit.psbtview import PSBTView
from embit.script import p2pkh, p2tr
from embit.transaction import (
    SIGHASH,
    Transaction,
    TransactionError,
    TransactionInput,
    TransactionOutput,
)

BIP341_HASH_TYPES = {0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83}
VALUE = 100000
KEY = ec.PrivateKey(b"\x42" * 32)
SPK = p2tr(KEY.get_public_key())


def unsigned_tx():
    return Transaction(
        vin=[TransactionInput(b"\x11" * 32, 0)],
        vout=[TransactionOutput(VALUE - 1000, SPK)],
    )


def serialized_psbt(sighash_type=None):
    psbt = PSBT(unsigned_tx())
    psbt.inputs[0].witness_utxo = TransactionOutput(VALUE, SPK)
    psbt.inputs[0].sighash_type = sighash_type
    return psbt.serialize()


class TaprootHashTypeTest(TestCase):
    def test_only_bip341_hash_types_give_a_digest(self):
        sighashers = (
            unsigned_tx(),
            PSBT.parse(serialized_psbt()),
            PSBTView.view(BytesIO(serialized_psbt())),
        )
        for sighasher in sighashers:
            for hash_type in range(256):
                args = (0, [SPK], [VALUE], hash_type)
                if hash_type in BIP341_HASH_TYPES:
                    self.assertEqual(len(sighasher.sighash_taproot(*args)), 32)
                else:
                    with self.assertRaises(TransactionError):
                        sighasher.sighash_taproot(*args)

    def test_psbt_asking_for_0x80_is_not_signed(self):
        psbt = PSBT.parse(serialized_psbt(SIGHASH.ANYONECANPAY))
        self.assertRaises(TransactionError, psbt.sign_with, KEY, sighash=None)
        self.assertIsNone(psbt.inputs[0].final_scriptwitness)
        self.assertEqual(
            PSBT.parse(serialized_psbt(SIGHASH.ANYONECANPAY)).sign_with(KEY), 0
        )

        view = PSBTView.view(BytesIO(serialized_psbt(SIGHASH.ANYONECANPAY)))
        sigs = BytesIO()
        self.assertRaises(TransactionError, view.sign_with, KEY, sigs, sighash=None)
        self.assertEqual(sigs.getvalue(), b"")

    def test_psbt_asking_for_a_defined_type_is_signed(self):
        hash_type = SIGHASH.ALL | SIGHASH.ANYONECANPAY
        psbt = PSBT.parse(serialized_psbt(hash_type))
        self.assertEqual(psbt.sign_with(KEY, sighash=None), 1)
        signature = psbt.inputs[0].final_scriptwitness.items[0]
        self.assertEqual(len(signature), 65)
        self.assertEqual(signature[64], hash_type)

    def test_legacy_and_segwit_v0_keep_0x80(self):
        script = p2pkh(KEY.get_public_key())
        tx = unsigned_tx()
        for digest in (
            tx.sighash_segwit(0, script, VALUE, sighash=SIGHASH.ANYONECANPAY),
            tx.sighash_legacy(0, script, sighash=SIGHASH.ANYONECANPAY),
        ):
            self.assertEqual(len(digest), 32)
