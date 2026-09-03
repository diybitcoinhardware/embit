"""Unified opt-in signature hash.

The digest is checked against Bitcoin Knots' cross-implementation vectors, and
the hash types the message defines are checked per script type.
"""
import io
import json
import os
from base64 import b64decode
from unittest import TestCase

from embit import bip32, ec, hashes, script
from embit.networks import NETWORKS
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
