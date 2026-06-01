"""
End-to-end Silent Payment signing tests via SilentPaymentsPSBT.sign_with().

This is the hardware-signer flow: the signer holds the key, sign_with()
populates per-input ECDH shares + DLEQ proofs for SP outputs and signs.

Covers:
  - P2WPKH single-sig signing verified against BIP-375 test vectors.
  - P2TR input + SP output is rejected (BIP-375 prohibits Segwit v>1).
  - Ineligible (bare-multisig P2SH) input produces no SP fields.
  - Explicit aux_rand threads through to DLEQ proof generation.
"""

import json
import unittest
from pathlib import Path

from embit import bip32, ec
from embit.silent_payments import dleq
from embit.psbt import DerivationPath
from embit.silent_payments import SilentPaymentsPSBT as PSBT
from embit.silent_payments.psbt import (
    SPInputScope as InputScope,
    SPOutputScope as OutputScope,
)
from embit.silent_payments import (
    SPValidationError,
    SilentPaymentData,
    get_eligible_inputs,
)
from embit.script import Script, p2wpkh, p2tr
from embit.transaction import TransactionOutput
from binascii import unhexlify

# ── test-vector helpers ────────────────────────────────────────────────────────


def _load_vectors():
    p = Path(__file__).parent / "data" / "bip375_test_vectors.json"
    if not p.exists():
        return []
    with open(p) as f:
        data = json.load(f)
    return data.get("valid", [])


def _find_vector(vectors, description_fragment):
    return next(
        (v for v in vectors if description_fragment in v["description"]),
        None,
    )


# ── fixtures ───────────────────────────────────────────────────────────────────


def _root():
    return bip32.HDKey.from_seed(bytes(range(32)))


def _sp_keys(scan_hex, spend_hex):
    scan = ec.PublicKey.parse(unhexlify(scan_hex))
    spend = ec.PublicKey.parse(unhexlify(spend_hex))
    return scan, spend


def _make_p2wpkh_psbt(root, scan_pub, spend_pub, value=100_000, txid_byte=0xAA):
    """
    Minimal PSBTv2 with one P2WPKH input and one SP output.

    tx_modifiable_flags is set to 0, required by BIP-375 when a
    script_pubkey is already present on an SP output.
    """
    child = root.derive([0, 0])
    pub = child.get_public_key()

    psbt = PSBT.create_v2()

    inp = InputScope()
    inp.txid = bytes([txid_byte] * 32)
    inp.vout = 0
    inp.sequence = 0xFFFFFFFE
    inp.witness_utxo = TransactionOutput(value=value, script_pubkey=p2wpkh(pub))
    inp.bip32_derivations[pub] = DerivationPath(root.my_fingerprint, [0, 0])
    psbt.add_input(inp)

    out = OutputScope()
    out.value = value - 1_000
    out.script_pubkey = Script(b"\x51\x20" + bytes(32))
    out.sp_data = SilentPaymentData(scan_pub, spend_pub)
    psbt.add_output(out)

    psbt.tx_modifiable_flags = 0

    return psbt, child


# ── end-to-end vector test ─────────────────────────────────────────────────────


class TestE2EP2WPKHFromVector(unittest.TestCase):
    """
    End-to-end signing test using data from the BIP-375 test vectors.

    We reconstruct input 0 (P2WPKH) of the "two inputs single-signer using
    per-input ECDH shares" vector.  The expected ECDH share is deterministic
    and must match the value in the test vector exactly.
    """

    PRIV_HEX = "7e31eeeb1aa2597b6d63b357541461d75ddae76b7603d24619f5ebed9e88ec31"
    PUB_HEX = "02c817bb7521afc35ea96f3bfb270e6eb50ddffa5560627b961fec00f2996508bf"
    SCAN_HEX = "027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068"
    SPEND_HEX = "0361e1b1e9de5e42cb2007f7ca54b9e0d57ed13938fad56d3f19e57513a8fce039"
    EXPECTED_SHARE_HEX = (
        "03eca4ff11b728e2e0f60ce6222943a6ff55b9d95f627bf9a99d084bc872d50a5b"
    )
    PREVOUT_TXID = "18a717663b0bab14b12a1a771323ff1e4079dd532e5dd13e28ea1081c700984a"

    @classmethod
    def setUpClass(cls):
        vectors = _load_vectors()
        cls.vector = _find_vector(
            vectors, "two inputs single-signer using per-input ECDH shares"
        )

    def _build_psbt(self):
        """
        Build a PSBTv2 matching vector input 0: a P2WPKH input controlled by
        PRIV_HEX, sending to the SCAN/SPEND SP output.  The raw signing key is
        loaded directly; sign_with() matches it to the input by script hash.
        """
        priv = ec.PrivateKey(unhexlify(self.PRIV_HEX))
        pub = priv.get_public_key()

        scan_pub, spend_pub = _sp_keys(self.SCAN_HEX, self.SPEND_HEX)

        psbt = PSBT.create_v2()

        inp = InputScope()
        inp.txid = unhexlify(self.PREVOUT_TXID)[::-1]
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2wpkh(pub))
        inp.bip32_derivations[pub] = DerivationPath(b"\x00\x00\x00\x00", [0, 0])
        psbt.add_input(inp)

        out = OutputScope()
        out.value = 95_000
        out.script_pubkey = Script(b"\x51\x20" + bytes(32))
        out.sp_data = SilentPaymentData(scan_pub, spend_pub)
        psbt.add_output(out)

        psbt.tx_modifiable_flags = 0

        return psbt, priv

    def test_ecdh_share_matches_vector(self):
        """ECDH share populated by sign_with() matches the test vector value."""
        if self.vector is None:
            self.skipTest("Test vector not found in bip375_test_vectors.json")

        psbt, priv = self._build_psbt()
        psbt.sign_with(priv)

        scan_key_bytes = unhexlify(self.SCAN_HEX)
        share = psbt.inputs[0].sp_ecdh_shares.get(scan_key_bytes)
        self.assertIsNotNone(share, "ECDH share not populated")
        self.assertEqual(share.hex(), self.EXPECTED_SHARE_HEX)

    def test_dleq_proof_valid(self):
        """DLEQ proof generated by sign_with() verifies correctly."""
        if self.vector is None:
            self.skipTest("Test vector not found in bip375_test_vectors.json")

        psbt, priv = self._build_psbt()
        psbt.sign_with(priv)

        scan_key_bytes = unhexlify(self.SCAN_HEX)
        share = psbt.inputs[0].sp_ecdh_shares[scan_key_bytes]
        proof = psbt.inputs[0].sp_dleq_proofs[scan_key_bytes]

        pub = ec.PublicKey.parse(unhexlify(self.PUB_HEX))
        C = ec.PublicKey.parse(share)
        self.assertTrue(
            dleq.verify_dleq_proof(
                pub.sec(), unhexlify(self.SCAN_HEX), C.sec(), proof
            )
        )

    def test_full_psbt_sign_produces_signature(self):
        """sign_with() also places a partial_sig on the input."""
        psbt, priv = self._build_psbt()
        count = psbt.sign_with(priv)
        self.assertGreater(count, 0)
        self.assertGreater(len(psbt.inputs[0].partial_sigs), 0)


# ── input eligibility ───────────────────────────────────────────────────────────


class TestInputEligibility(unittest.TestCase):
    """BIP-375 input eligibility constraints for SP outputs."""

    SCAN_HEX = "027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068"
    SPEND_HEX = "0361e1b1e9de5e42cb2007f7ca54b9e0d57ed13938fad56d3f19e57513a8fce039"

    def _scan_spend(self):
        return _sp_keys(self.SCAN_HEX, self.SPEND_HEX)

    def test_p2tr_input_is_eligible(self):
        """P2TR (Segwit v1) is an eligible SP input per BIP-352/BIP-375."""
        root = _root()
        child = root.derive([0, 0])
        pub = child.get_public_key()
        scan_pub, spend_pub = self._scan_spend()

        psbt = PSBT.create_v2()

        inp = InputScope()
        inp.txid = bytes([0xBB] * 32)
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2tr(pub))
        inp.taproot_internal_key = pub
        inp.bip32_derivations[pub] = DerivationPath(root.my_fingerprint, [0, 0])
        psbt.add_input(inp)

        out = OutputScope()
        out.value = 99_000
        out.script_pubkey = Script(b"\x51\x20" + bytes(32))
        out.sp_data = SilentPaymentData(scan_pub, spend_pub)
        psbt.add_output(out)

        psbt.tx_modifiable_flags = 0

        self.assertEqual(get_eligible_inputs(psbt.inputs, has_sp_outputs=True), [0])

    def test_segwit_v2_input_raises(self):
        """An input spending a Segwit v>1 output with SP outputs must fail."""
        root = _root()
        scan_pub, spend_pub = self._scan_spend()

        psbt = PSBT.create_v2()

        inp = InputScope()
        inp.txid = bytes([0xBD] * 32)
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        # OP_2 <20-byte program> = witness version 2
        v2_script = Script(b"\x52\x14" + bytes(20))
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=v2_script)
        psbt.add_input(inp)

        out = OutputScope()
        out.value = 99_000
        out.script_pubkey = Script(b"\x51\x20" + bytes(32))
        out.sp_data = SilentPaymentData(scan_pub, spend_pub)
        psbt.add_output(out)

        psbt.tx_modifiable_flags = 0

        with self.assertRaises(SPValidationError):
            get_eligible_inputs(psbt.inputs, has_sp_outputs=True)

    def test_multisig_p2sh_input_produces_no_sp_fields(self):
        """
        A P2SH bare-multisig input is ineligible for SP (not P2WPKH/P2PKH/
        P2SH-P2WPKH).  sign_with() completes without adding SP fields for it.
        """
        root = _root()
        child1 = root.derive([0, 0])
        child2 = root.derive([0, 1])
        pub1 = child1.get_public_key()
        pub2 = child2.get_public_key()
        scan_pub, spend_pub = self._scan_spend()

        # OP_1 <33-byte-pub1> <33-byte-pub2> OP_2 OP_CHECKMULTISIG
        redeem_raw = (
            bytes([0x51])
            + bytes([0x21])
            + pub1.sec()
            + bytes([0x21])
            + pub2.sec()
            + bytes([0x52, 0xAE])
        )
        from embit.script import p2sh

        redeem = Script(redeem_raw)
        p2sh_script = p2sh(redeem)

        psbt = PSBT.create_v2()

        inp = InputScope()
        inp.txid = bytes([0xCC] * 32)
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2sh_script)
        inp.redeem_script = redeem
        inp.bip32_derivations[pub1] = DerivationPath(root.my_fingerprint, [0, 0])
        inp.bip32_derivations[pub2] = DerivationPath(root.my_fingerprint, [0, 1])
        psbt.add_input(inp)

        out = OutputScope()
        out.value = 99_000
        out.script_pubkey = Script(b"\x51\x20" + bytes(32))
        out.sp_data = SilentPaymentData(scan_pub, spend_pub)
        psbt.add_output(out)

        psbt.tx_modifiable_flags = 0

        psbt.sign_with(root)
        self.assertEqual(len(psbt.inputs[0].sp_ecdh_shares), 0)
        self.assertEqual(len(psbt.inputs[0].sp_dleq_proofs), 0)


# ── aux_rand threading ──────────────────────────────────────────────────────────


class TestAuxRand(unittest.TestCase):

    def setUp(self):
        self.root = _root()
        scan_pub, spend_pub = _sp_keys(
            "027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068",
            "0361e1b1e9de5e42cb2007f7ca54b9e0d57ed13938fad56d3f19e57513a8fce039",
        )
        self.psbt, self.child = _make_p2wpkh_psbt(self.root, scan_pub, spend_pub)
        self.scan_key_bytes = scan_pub.sec()

    def test_aux_rand_deterministic(self):
        """Explicit aux_rand makes the DLEQ proof deterministic across runs."""
        aux = bytes(range(32))

        psbt_a, _ = _make_p2wpkh_psbt(
            self.root,
            ec.PublicKey.parse(
                unhexlify(
                    "027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068"
                )
            ),
            ec.PublicKey.parse(
                unhexlify(
                    "0361e1b1e9de5e42cb2007f7ca54b9e0d57ed13938fad56d3f19e57513a8fce039"
                )
            ),
            txid_byte=0x01,
        )
        psbt_b, _ = _make_p2wpkh_psbt(
            self.root,
            ec.PublicKey.parse(
                unhexlify(
                    "027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068"
                )
            ),
            ec.PublicKey.parse(
                unhexlify(
                    "0361e1b1e9de5e42cb2007f7ca54b9e0d57ed13938fad56d3f19e57513a8fce039"
                )
            ),
            txid_byte=0x01,
        )

        psbt_a._sign_with_sp(self.root, aux_rand=aux)
        psbt_b._sign_with_sp(self.root, aux_rand=aux)

        proof_a = psbt_a.inputs[0].sp_dleq_proofs[self.scan_key_bytes]
        proof_b = psbt_b.inputs[0].sp_dleq_proofs[self.scan_key_bytes]
        self.assertEqual(proof_a, proof_b)
