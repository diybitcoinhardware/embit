"""Unified opt-in signature hash.

Two things are covered, and the second is the one that matters: the digest is
checked against Bitcoin Knots' cross-implementation vectors, and the hash type
negotiation in sign_with is table-tested. Every defect found in this feature so
far has been in the negotiation rather than the digest, which vector coverage
alone cannot catch.
"""
import io
import json
import os
from base64 import b64decode
from unittest import TestCase

from embit import bip32, ec, hashes, script
from embit.networks import NETWORKS
from embit.psbt import PSBT, PSBTError, DerivationPath
from embit.psbtview import PSBTView
from embit.transaction import (
    SIGHASH,
    UNIFIED_SCRIPT_TYPE,
    Transaction,
    TransactionError,
    TransactionInput,
    TransactionOutput,
)

VECTORS = os.path.join(os.path.dirname(__file__), "data", "unified_sighash.json")
UNIFIED_ALL = SIGHASH.ALL | SIGHASH.UNIFIED
ROOT = bip32.HDKey.from_seed(b"\x01" * 32, version=NETWORKS["regtest"]["xprv"])
CHILD = ROOT.derive("m/84h/1h/0h/0/0")
SPK = script.p2wpkh(CHILD.key.get_public_key())


def load_vectors():
    with open(VECTORS) as f:
        rows = json.load(f)
    header, rows = rows[0], rows[1:]
    return [dict(zip(header, r)) for r in rows]


def vector_digest(v):
    tx = Transaction.parse(bytes.fromhex(v["rawTx"]))
    values = [amount for amount, _ in v["spentOutputs"]]
    spks = [script.Script(bytes.fromhex(spk)) for _, spk in v["spentOutputs"]]
    kwargs = {}
    if v["scriptType"] in (UNIFIED_SCRIPT_TYPE.BARE, UNIFIED_SCRIPT_TYPE.WITNESS_V0):
        kwargs["script_code"] = script.Script(bytes.fromhex(v["scriptCode"]))
    elif v["scriptType"] == UNIFIED_SCRIPT_TYPE.TAPSCRIPT:
        leaf = script.Script(bytes.fromhex(v["scriptCode"]))
        kwargs["tapleaf_hash"] = hashes.tagged_hash(
            "TapLeaf", bytes([0xC0]) + leaf.serialize()
        )
    return tx.sighash_unified(
        v["inIdx"], v["scriptType"], spks, values, v["hashType"], **kwargs
    )


def one_input_psbt(declared, value=100000):
    tx = Transaction(
        vin=[TransactionInput(bytes.fromhex("aa" * 32), 0, sequence=0xFFFFFFFE)],
        vout=[TransactionOutput(90000, SPK)],
    )
    psbt = PSBT(tx)
    psbt.inputs[0].witness_utxo = TransactionOutput(value, SPK)
    psbt.inputs[0].bip32_derivations[CHILD.key.get_public_key()] = DerivationPath(
        ROOT.child(0).fingerprint, bip32.parse_path("m/84h/1h/0h/0/0")
    )
    psbt.inputs[0].sighash_type = declared
    return psbt


class UnifiedSighashVectors(TestCase):
    def test_matches_knots(self):
        vectors = load_vectors()
        self.assertEqual(len(vectors), 166)
        for i, v in enumerate(vectors):
            self.assertEqual(
                vector_digest(v).hex(),
                v["sighash"],
                "vector %d: scriptType=%d hashType=%s"
                % (i, v["scriptType"], hex(v["hashType"])),
            )

    def test_all_four_script_types_are_covered(self):
        kinds = {v["scriptType"] for v in load_vectors()}
        self.assertEqual(kinds, {0, 1, 2, 3})

    def test_script_type_separates_domains(self):
        """If this failed the vector check above would be vacuous."""
        v = next(x for x in load_vectors() if x["scriptType"] == UNIFIED_SCRIPT_TYPE.BARE)
        wrong = dict(v, scriptType=UNIFIED_SCRIPT_TYPE.WITNESS_V0)
        self.assertNotEqual(vector_digest(wrong).hex(), v["sighash"])


class CheckUnified(TestCase):
    def test_accepts_defined_hash_types(self):
        for ht in (0x21, 0x22, 0x23, 0xA1, 0xA2, 0xA3):
            SIGHASH.check_unified(ht)

    def test_rejects_without_the_opt_in_bit(self):
        for ht in (0x00, 0x01, 0x02, 0x03, 0x81, -1, -223):
            with self.assertRaises(TransactionError, msg="accepted %s" % hex(ht)):
                SIGHASH.check_unified(ht)

    def test_bare_and_witness_v0_read_the_byte_as_legacy_does(self):
        # Anything that is not NONE or SINGLE means ALL, and unknown bits ride
        # along, so these are accepted for script types 0 and 1.
        for ht in (0x20, 0x24, 0x25, 0x2F, 0x61, 0xFF):
            for script_type in (0, 1):
                sh, _ = SIGHASH.check_unified(ht, script_type)
                self.assertEqual(sh, ht & 0x1F)

    def test_taproot_keeps_bip341s_reading(self):
        # BIP341 defines no meaning for these, so they stay reserved there.
        for ht in (0x20, 0x24, 0x25, 0x2F, 0x61, 0xFF):
            for script_type in (2, 3):
                with self.assertRaises(TransactionError, msg="accepted %s" % hex(ht)):
                    SIGHASH.check_unified(ht, script_type)


class UnifiedSighashErrors(TestCase):
    def _tx(self, n_out=1):
        return Transaction(
            vin=[TransactionInput(bytes.fromhex("aa" * 32), 0, sequence=0xFFFFFFFE)],
            vout=[TransactionOutput(90000, SPK)] * n_out,
        )

    def test_single_without_matching_output(self):
        tx = self._tx(n_out=0)
        with self.assertRaises(TransactionError):
            tx.sighash_unified(
                0, UNIFIED_SCRIPT_TYPE.BARE, [SPK], [100000],
                SIGHASH.SINGLE | SIGHASH.UNIFIED, script_code=SPK,
            )

    def test_out_of_range_input_index(self):
        with self.assertRaises(TransactionError):
            self._tx().sighash_unified(
                5, UNIFIED_SCRIPT_TYPE.BARE, [SPK], [100000], UNIFIED_ALL,
                script_code=SPK,
            )

    def test_script_code_required_for_bare_and_segwit(self):
        for st in (UNIFIED_SCRIPT_TYPE.BARE, UNIFIED_SCRIPT_TYPE.WITNESS_V0):
            with self.assertRaises(TransactionError):
                self._tx().sighash_unified(0, st, [SPK], [100000], UNIFIED_ALL)

    def test_tapleaf_hash_required_for_tapscript(self):
        with self.assertRaises(TransactionError):
            self._tx().sighash_unified(
                0, UNIFIED_SCRIPT_TYPE.TAPSCRIPT, [SPK], [100000], UNIFIED_ALL
            )


class MissingSiblingUtxo(TestCase):
    """A PSBT lacking sibling UTXO data must raise PSBTError, not AttributeError:
    on a signing device the difference is a rejection versus a crash."""

    def _two_inputs(self, with_sibling):
        tx = Transaction(
            vin=[
                TransactionInput(bytes.fromhex("aa" * 32), 0, sequence=0xFFFFFFFE),
                TransactionInput(bytes.fromhex("bb" * 32), 0, sequence=0xFFFFFFFE),
            ],
            vout=[TransactionOutput(150000, SPK)],
        )
        psbt = PSBT(tx)
        psbt.inputs[0].witness_utxo = TransactionOutput(100000, SPK)
        if with_sibling:
            psbt.inputs[1].witness_utxo = TransactionOutput(200000, SPK)
        return psbt

    def test_raises_psbterror(self):
        with self.assertRaises(PSBTError):
            self._two_inputs(False).sighash(0, sighash=UNIFIED_ALL)

    def test_anyonecanpay_does_not_need_siblings(self):
        acp = SIGHASH.ANYONECANPAY | UNIFIED_ALL
        without = self._two_inputs(False).sighash(0, sighash=acp)
        with_ = self._two_inputs(True).sighash(0, sighash=acp)
        # the message carries no sibling amounts, so the data cannot matter
        self.assertEqual(without, with_)

    def test_non_anyonecanpay_commits_to_siblings(self):
        a = self._two_inputs(True).sighash(0, sighash=UNIFIED_ALL)
        psbt = self._two_inputs(True)
        psbt.inputs[1].witness_utxo = TransactionOutput(999999, SPK)
        self.assertNotEqual(a, psbt.sighash(0, sighash=UNIFIED_ALL))


def signed_byte(psbt):
    sigs = list(psbt.inputs[0].partial_sigs.values())
    return sigs[0][-1] if sigs else None


class SignWithNegotiation(TestCase):
    """(declared, requested) -> hash type byte, or None for no signature."""

    CASES = [
        (SIGHASH.ALL, UNIFIED_ALL, 0x21),
        (UNIFIED_ALL, UNIFIED_ALL, 0x21),
        (SIGHASH.DEFAULT, UNIFIED_ALL, 0x21),
        (None, UNIFIED_ALL, 0x21),
        # SIGHASH.DEFAULT names no hash type, so the PSBT's request stands.
        (UNIFIED_ALL, SIGHASH.DEFAULT, 0x21),
        # A named plain hash type does refuse it.
        (UNIFIED_ALL, SIGHASH.ALL, 0x01),
        (SIGHASH.ALL, SIGHASH.DEFAULT, 0x01),
        (SIGHASH.NONE, UNIFIED_ALL, None),
        (SIGHASH.SINGLE, UNIFIED_ALL, None),
        (SIGHASH.NONE | SIGHASH.UNIFIED, UNIFIED_ALL, None),
    ]

    def test_matrix(self):
        for declared, requested, expected in self.CASES:
            psbt = one_input_psbt(declared)
            psbt.sign_with(ROOT, sighash=requested)
            self.assertEqual(
                signed_byte(psbt), expected,
                "declared=%s requested=%s" % (declared, hex(requested)),
            )

    def test_none_defers_to_the_psbt(self):
        psbt = one_input_psbt(UNIFIED_ALL)
        psbt.sign_with(ROOT, sighash=None)
        self.assertEqual(signed_byte(psbt), 0x21)

    def test_untouched_default_honours_the_opt_in(self):
        """The call every caller predating the hardfork already makes.

        Stripping the opt-in here would hand back a legacy signature for a PSBT
        that asked for replay protection, and return a success count while doing
        it. Opting in only widens what the signature commits to, so there is
        nothing to protect the caller from.
        """
        psbt = one_input_psbt(UNIFIED_ALL)
        psbt.sign_with(ROOT)
        self.assertEqual(signed_byte(psbt), 0x21)

    def test_a_named_hash_type_still_refuses_the_opt_in(self):
        """The caller chooses the algorithm when it names one."""
        psbt = one_input_psbt(UNIFIED_ALL)
        psbt.sign_with(ROOT, sighash=SIGHASH.ALL)
        self.assertEqual(signed_byte(psbt), 0x01)

    def test_a_declared_0x20_is_a_hash_type_of_its_own(self):
        """Bare and segwit v0 read the byte the legacy way, so 0x20 means ALL
        with a message of its own. Folding it into 0x21 would sign something
        other than what the PSBT asked for."""
        psbt = one_input_psbt(SIGHASH.UNIFIED)
        psbt.sign_with(ROOT, sighash=None)
        self.assertEqual(signed_byte(psbt), 0x20)


class RecordedSighashType(TestCase):
    """A signer records the type it actually signed with, so the field and the
    hash type byte on the signature agree."""

    def test_opting_in_is_declared(self):
        psbt = one_input_psbt(None)
        psbt.sign_with(ROOT, sighash=UNIFIED_ALL)
        self.assertEqual(signed_byte(psbt), 0x21)
        self.assertEqual(psbt.inputs[0].sighash_type, 0x21)

    def test_a_plain_all_psbt_that_opts_in_is_updated(self):
        psbt = one_input_psbt(SIGHASH.ALL)
        psbt.sign_with(ROOT, sighash=UNIFIED_ALL)
        self.assertEqual(signed_byte(psbt), 0x21)
        self.assertEqual(psbt.inputs[0].sighash_type, 0x21)

    def test_legacy_signing_leaves_the_field_alone(self):
        """Confined to the opt-in: signing that does not involve it must not
        start writing a field the PSBT never carried."""
        psbt = one_input_psbt(None)
        psbt.sign_with(ROOT, sighash=SIGHASH.ALL)
        self.assertEqual(signed_byte(psbt), 0x01)
        self.assertIsNone(psbt.inputs[0].sighash_type)

    def test_an_input_this_call_did_not_sign_is_untouched(self):
        """A key that signs nothing must not rewrite a co-signer's declaration."""
        psbt = one_input_psbt(SIGHASH.ALL)
        other = bip32.HDKey.from_seed(b"\x02" * 32, version=NETWORKS["regtest"]["xprv"])
        self.assertEqual(psbt.sign_with(other, sighash=UNIFIED_ALL), 0)
        self.assertEqual(psbt.inputs[0].sighash_type, SIGHASH.ALL)


class PSBTViewParity(TestCase):
    """PSBTView is the streaming API for constrained signers. It must produce
    the same digest as PSBT or a signer gets different results per class."""

    def setUp(self):
        tx = Transaction(
            vin=[
                TransactionInput(bytes.fromhex("aa" * 32), 0, sequence=0xFFFFFFFE),
                TransactionInput(bytes.fromhex("bb" * 32), 0, sequence=0xFFFFFFFE),
            ],
            vout=[TransactionOutput(150000, SPK), TransactionOutput(120000, SPK)],
        )
        self.psbt = PSBT(tx)
        self.psbt.inputs[0].witness_utxo = TransactionOutput(100000, SPK)
        self.psbt.inputs[1].witness_utxo = TransactionOutput(200000, SPK)

    def view(self):
        return PSBTView.view(io.BytesIO(b64decode(self.psbt.to_string())))

    def test_digests_match(self):
        for ht in (0x21, 0xA1, 0x22, 0x23, 0xA3):
            for i in (0, 1):
                self.assertEqual(
                    self.psbt.sighash(i, sighash=ht),
                    self.view().sighash(i, sighash=ht),
                    "hash type %s input %d" % (hex(ht), i),
                )

    def test_legacy_digests_unchanged(self):
        for ht in (0x01, 0x81, 0x03):
            self.assertEqual(
                self.psbt.sighash(0, sighash=ht),
                self.view().sighash(0, sighash=ht),
            )

    def test_negotiation_matches_sign_with(self):
        """The streaming signer must reach the same hash type byte, or a signer
        gets replay protection or not depending on which class it used."""
        for requested, expected in ((None, 0x21), (SIGHASH.ALL, 0x01)):
            psbt = one_input_psbt(UNIFIED_ALL)
            view = PSBTView.view(io.BytesIO(b64decode(psbt.to_string())))
            stream = io.BytesIO()
            kwargs = {} if requested is None else {"sighash": requested}
            self.assertEqual(view.sign_input(0, ROOT, stream, **kwargs), 1)
            self.assertEqual(stream.getvalue()[-1], expected, repr(requested))

            psbt.sign_with(ROOT, **kwargs)
            self.assertEqual(signed_byte(psbt), expected, repr(requested))
