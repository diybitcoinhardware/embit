"""A signature is made over witness_script or redeem_script when an input
carries one. These tests check that both are tied to the scriptPubKey of the
output the input spends, through PSBT and PSBTView, for PSBTv0 and PSBTv2.
"""

from io import BytesIO
from unittest import TestCase

from embit import bip32, ec, script
from embit.psbt import PSBT, DerivationPath, InputScope, PSBTError
from embit.psbtview import PSBTView
from embit.transaction import (
    SIGHASH,
    Transaction,
    TransactionInput,
    TransactionOutput,
)

ROOT = bip32.HDKey.from_seed(b"embit script commitment tests 01")
PATH = bip32.parse_path("m/48h/1h/0h/2h/0/0")
KEY = ROOT.derive(PATH).to_public().key
OTHER = (
    bip32.HDKey.from_seed(b"embit script commitment tests 02")
    .derive(PATH)
    .to_public()
    .key
)
VALUE = 100000

# two different scripts that both use KEY
MULTISIG = script.multisig(2, [KEY, OTHER])
ANOTHER = script.multisig(1, [KEY, OTHER])
EMPTY = script.Script(b"")

# what a signature for KEY has to commit to when it spends a single key output
P2PKH = script.p2pkh(KEY)
P2WPKH = script.p2wpkh(KEY)

# name, scriptPubKey, redeem script, witness script, legacy, signed script
MATCHING = [
    ("p2pkh", P2PKH, None, None, True, P2PKH),
    ("p2wpkh", P2WPKH, None, None, False, P2PKH),
    ("p2sh-p2wpkh", script.p2sh(P2WPKH), P2WPKH, None, False, P2PKH),
    ("p2sh", script.p2sh(MULTISIG), MULTISIG, None, True, MULTISIG),
    ("p2wsh", script.p2wsh(MULTISIG), None, MULTISIG, False, MULTISIG),
    (
        "p2sh-p2wsh",
        script.p2sh(script.p2wsh(MULTISIG)),
        script.p2wsh(MULTISIG),
        MULTISIG,
        False,
        MULTISIG,
    ),
    (
        "p2sh-p2wsh without the redeem script",
        script.p2sh(script.p2wsh(MULTISIG)),
        None,
        MULTISIG,
        False,
        MULTISIG,
    ),
]

# name, scriptPubKey, redeem script, witness script, legacy, error
MISMATCHED = [
    # a single key output declared for a multisig coin: a segwit v0
    # signature does not cover the scriptPubKey, so it would be valid for
    # the p2wsh output of the same value at the same outpoint
    ("witness script on p2wpkh", P2WPKH, None, MULTISIG, False, "Witness"),
    ("witness script on p2pkh", P2PKH, None, MULTISIG, False, "Witness"),
    (
        "witness script of another p2wsh",
        script.p2wsh(MULTISIG),
        None,
        ANOTHER,
        False,
        "Witness",
    ),
    (
        "witness script not in the redeem script",
        script.p2sh(script.p2wsh(MULTISIG)),
        script.p2wsh(MULTISIG),
        ANOTHER,
        False,
        "Witness",
    ),
    (
        "witness script of another p2sh-p2wsh, no redeem script",
        script.p2sh(script.p2wsh(MULTISIG)),
        None,
        ANOTHER,
        False,
        "Witness",
    ),
    (
        "witness script next to a plain p2sh redeem script",
        script.p2sh(MULTISIG),
        MULTISIG,
        MULTISIG,
        True,
        "Witness",
    ),
    (
        "redeem script of another p2sh",
        script.p2sh(MULTISIG),
        ANOTHER,
        None,
        True,
        "Redeem",
    ),
    ("redeem script on p2wpkh", P2WPKH, P2WPKH, None, False, "Redeem"),
    ("redeem script on p2pkh", P2PKH, MULTISIG, None, True, "Redeem"),
    # an empty script is still a script the input carries
    ("empty redeem script on p2wpkh", P2WPKH, EMPTY, None, False, "Redeem"),
    ("empty redeem script on p2sh", script.p2sh(MULTISIG), EMPTY, None, True, "Redeem"),
    ("empty witness script on p2wpkh", P2WPKH, None, EMPTY, False, "Witness"),
    (
        "empty witness script on p2wsh",
        script.p2wsh(MULTISIG),
        None,
        EMPTY,
        False,
        "Witness",
    ),
]


def build(version, script_pubkey, redeem_script, witness_script, legacy):
    """Returns the transaction and a serialized PSBT with one input that
    spends script_pubkey, carries the given scripts and names KEY."""
    utxo = TransactionOutput(VALUE, script_pubkey)
    prev = Transaction(vin=[TransactionInput(b"\x11" * 32, 0)], vout=[utxo])
    tx = Transaction(
        vin=[TransactionInput(prev.txid(), 0)],
        vout=[TransactionOutput(VALUE - 1000, script.p2wpkh(OTHER))],
    )
    psbt = PSBT(tx, version=version)
    inp = psbt.inputs[0]
    if legacy:
        inp.non_witness_utxo = prev
    else:
        inp.witness_utxo = utxo
    inp.redeem_script = redeem_script
    inp.witness_script = witness_script
    inp.bip32_derivations[KEY] = DerivationPath(ROOT.my_fingerprint, PATH)
    return tx, psbt.serialize()


class ScriptCommitmentTest(TestCase):
    def refused(self, error, func, *args):
        """func has to raise a PSBTError that names the script"""
        try:
            func(*args)
        except PSBTError as e:
            self.assertIn(error + " script doesn't match scriptPubKey", str(e))
            return
        self.assertTrue(False, "PSBTError not raised")

    def test_matching_scripts_sign(self):
        """Scripts the output commits to are verified and signed as before"""
        for version in (None, 2):
            for name, spk, redeem, witness, legacy, signed in MATCHING:
                msg = "%s, version %s" % (name, version)
                tx, raw = build(version, spk, redeem, witness, legacy)

                psbt = PSBT.parse(raw)
                self.assertEqual(psbt.verify(ignore_missing=True), legacy, msg)
                self.assertTrue(psbt.inputs[0].verify_scripts(), msg)
                self.assertEqual(psbt.sign_with(ROOT), 1, msg)
                sig = psbt.inputs[0].partial_sigs[KEY]
                if legacy:
                    digest = tx.sighash_legacy(0, signed, sighash=SIGHASH.ALL)
                else:
                    digest = tx.sighash_segwit(0, signed, VALUE, sighash=SIGHASH.ALL)
                self.assertTrue(KEY.verify(ec.Signature.parse(sig[:-1]), digest), msg)

                sigs = BytesIO()
                view = PSBTView.view(BytesIO(raw))
                self.assertEqual(view.sign_with(ROOT, sigs), 1, msg)
                self.assertIn(sig, sigs.getvalue(), msg)

    def test_mismatched_scripts_are_refused(self):
        """A script the output does not commit to is neither verified nor signed"""
        for version in (None, 2):
            for name, spk, redeem, witness, legacy, error in MISMATCHED:
                msg = "%s, version %s" % (name, version)
                _, raw = build(version, spk, redeem, witness, legacy)

                psbt = PSBT.parse(raw)
                self.refused(error, psbt.verify, True)
                self.assertFalse(psbt.is_verified, msg)
                self.refused(error, psbt.inputs[0].verify_scripts)
                self.refused(error, psbt.sign_with, ROOT)
                self.assertEqual(len(psbt.inputs[0].partial_sigs), 0, msg)

                sigs = BytesIO()
                view = PSBTView.view(BytesIO(raw))
                self.refused(error, view.sign_with, ROOT, sigs)
                self.refused(error, view.sign_input, 0, ROOT, sigs)
                self.refused(error, view.input(0).verify, True)
                self.assertEqual(sigs.getvalue().find(KEY.sec()), -1, msg)

    def test_missing_scripts_are_not_an_error(self):
        """verify_scripts() only judges the scripts an input carries"""
        # no previous output to compare with
        self.assertFalse(InputScope().verify_scripts())
        # outputs whose script is not in the PSBT
        for spk in (script.p2wsh(MULTISIG), script.p2sh(MULTISIG)):
            inp = InputScope()
            inp.witness_utxo = TransactionOutput(VALUE, spk)
            self.assertTrue(inp.verify_scripts())
            self.assertFalse(inp.verify(ignore_missing=True))

    def test_merged_scripts_are_not_verified(self):
        """is_verified does not vouch for a script merged after verify()"""
        for spk, field, error in (
            (script.p2sh(MULTISIG), "redeem_script", "Redeem"),
            (script.p2wsh(MULTISIG), "witness_script", "Witness"),
        ):
            for merged in (MULTISIG, ANOTHER):
                _, raw = build(None, spk, None, None, True)
                psbt = PSBT.parse(raw)
                self.assertTrue(psbt.verify(), field)
                extra = InputScope()
                setattr(extra, field, merged)
                psbt.inputs[0].update(extra)
                self.assertFalse(psbt.is_verified, field)
                if merged == MULTISIG:
                    self.assertTrue(psbt.verify(), field)
                else:
                    self.refused(error, psbt.verify)
                    self.assertFalse(psbt.is_verified, field)

    def test_taproot_output_with_a_script(self):
        """A v0 script on an output that cannot commit to it is refused by
        verify() and by signing, though a taproot signature does not hash it"""
        for version in (None, 2):
            # without the script the key path is signed
            _, raw = build(version, script.p2tr(KEY), None, None, False)
            self.assertEqual(PSBT.parse(raw).sign_with(ROOT), 1)
            self.assertEqual(PSBTView.view(BytesIO(raw)).sign_with(ROOT, BytesIO()), 1)

            for redeem, witness, error in (
                (None, MULTISIG, "Witness"),
                (MULTISIG, None, "Redeem"),
            ):
                _, raw = build(version, script.p2tr(KEY), redeem, witness, False)
                psbt = PSBT.parse(raw)
                self.refused(error, psbt.verify, True)
                self.refused(error, psbt.sign_with, ROOT)
                self.assertIsNone(psbt.inputs[0].taproot_key_sig)

                sigs = BytesIO()
                view = PSBTView.view(BytesIO(raw))
                self.refused(error, view.sign_with, ROOT, sigs)
                self.assertEqual(sigs.getvalue(), b"")
