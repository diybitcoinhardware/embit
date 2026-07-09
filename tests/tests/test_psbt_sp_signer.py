"""
End-to-end Silent Payment signing tests via SilentPaymentsPSBT.sign_with().

This is the hardware-signer flow: the signer holds the key, sign_with()
populates per-input ECDH shares + DLEQ proofs for SP outputs and signs.

Covers:
  - P2WPKH single-sig signing verified against BIP-375 test vectors.
  - P2TR input + SP output is eligible (BIP-352); only Segwit v>1 is rejected.
  - Ineligible (bare-multisig P2SH) input produces no SP fields.
  - Explicit aux_rand threads through to DLEQ proof generation.
  - BIP-376 spend-from: signing a received SP UTXO and contributing its
    even-Y tweaked key to a new SP output (self-transfer).
"""

import json
import unittest
from pathlib import Path

from embit import bip32, ec
from embit.silent_payments import dleq
from embit.psbt import DerivationPath, TxModifiable, derive_hdkey
from embit.silent_payments import SilentPaymentsPSBT as PSBT
from embit.silent_payments.signing import match_sp_spend_base, resolve_input_privkey
from embit.silent_payments.psbt import (
    SPInputScope as InputScope,
    SPOutputScope as OutputScope,
)
from embit.silent_payments import (
    SPValidationError,
    SilentPaymentData,
    get_eligible_inputs,
)
from embit.script import Script, p2sh, p2wpkh, p2tr
from embit.transaction import TransactionOutput
from binascii import unhexlify


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


def _root():
    return bip32.HDKey.from_seed(bytes(range(32)))


def _sp_keys(scan_hex, spend_hex):
    scan = ec.PublicKey.parse(unhexlify(scan_hex))
    spend = ec.PublicKey.parse(unhexlify(spend_hex))
    return scan, spend


def _make_p2wpkh_psbt(root, scan_pub, spend_pub, value=100_000, txid_byte=0xAA):
    """Minimal PSBTv2 with one P2WPKH input and one SP output."""
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
    out.sp_data = SilentPaymentData(scan_pub, spend_pub)
    psbt.add_output(out)

    return psbt, child


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
        out.sp_data = SilentPaymentData(scan_pub, spend_pub)
        psbt.add_output(out)

        return psbt, priv

    def test_ecdh_share_matches_vector(self):
        """ECDH share populated by sign_with() matches the test vector value."""
        if self.vector is None:
            self.skipTest("Test vector not found in bip375_test_vectors.json")

        psbt, priv = self._build_psbt()
        psbt.sign_with(priv)

        scan_key_bytes = unhexlify(self.SCAN_HEX)
        share = psbt.sp_ecdh_shares.get(scan_key_bytes)
        self.assertIsNotNone(share, "ECDH share not populated")
        self.assertEqual(share.hex(), self.EXPECTED_SHARE_HEX)

    def test_dleq_proof_valid(self):
        """DLEQ proof generated by sign_with() verifies correctly."""
        if self.vector is None:
            self.skipTest("Test vector not found in bip375_test_vectors.json")

        psbt, priv = self._build_psbt()
        psbt.sign_with(priv)

        scan_key_bytes = unhexlify(self.SCAN_HEX)
        share = psbt.sp_ecdh_shares[scan_key_bytes]
        proof = psbt.sp_dleq_proofs[scan_key_bytes]

        pub = ec.PublicKey.parse(unhexlify(self.PUB_HEX))
        C = ec.PublicKey.parse(share)
        self.assertTrue(
            dleq.verify_dleq_proof(pub.sec(), unhexlify(self.SCAN_HEX), C.sec(), proof)
        )

    def test_full_psbt_sign_produces_signature(self):
        """sign_with() also places a partial_sig on the input."""
        psbt, priv = self._build_psbt()
        count = psbt.sign_with(priv)
        self.assertGreater(count, 0)
        self.assertGreater(len(psbt.inputs[0].partial_sigs), 0)


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
        out.sp_data = SilentPaymentData(scan_pub, spend_pub)
        psbt.add_output(out)

        self.assertEqual(get_eligible_inputs(psbt.inputs), [0])

    def test_segwit_v2_input_raises(self):
        """An input spending a Segwit v>1 output with SP outputs must fail."""
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
        out.sp_data = SilentPaymentData(scan_pub, spend_pub)
        psbt.add_output(out)

        with self.assertRaises(SPValidationError):
            psbt.validate_sp()

    def _p2sh_psbt(self, script_pubkey, redeem_script=None):
        """One P2SH input paying to script_pubkey, one SP output."""
        scan_pub, spend_pub = self._scan_spend()

        psbt = PSBT.create_v2()

        inp = InputScope()
        inp.txid = bytes([0xC5] * 32)
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=script_pubkey)
        inp.redeem_script = redeem_script
        psbt.add_input(inp)

        out = OutputScope()
        out.value = 99_000
        out.sp_data = SilentPaymentData(scan_pub, spend_pub)
        psbt.add_output(out)
        return psbt

    def test_p2sh_without_redeem_script_raises(self):
        """A P2SH input with no PSBT_IN_REDEEM_SCRIPT leaves eligibility
        undetermined, which must abort rather than default to ineligible."""
        from embit.script import p2sh

        pub = _root().derive([0, 0]).get_public_key()
        psbt = self._p2sh_psbt(p2sh(p2wpkh(pub)))

        with self.assertRaises(SPValidationError):
            get_eligible_inputs(psbt.inputs)

    def test_p2sh_redeem_script_not_matching_scriptpubkey_raises(self):
        """PSBT fields are unauthenticated, so a declared P2WPKH redeem script
        must not make a P2SH-multisig input eligible: only the scriptPubKey
        comes from the UTXO, and without checking it a_sum silently gains a key
        the real transaction never commits to."""
        from embit.script import multisig, p2sh

        root = _root()
        pub1 = root.derive([0, 0]).get_public_key()
        pub2 = root.derive([0, 1]).get_public_key()
        psbt = self._p2sh_psbt(
            # The UTXO pays to a 1-of-2 multisig, which is ineligible ...
            p2sh(multisig(1, [pub1, pub2])),
            # ... but the PSBT claims an eligible P2WPKH redeem script.
            redeem_script=p2wpkh(pub1),
        )

        with self.assertRaises(SPValidationError):
            get_eligible_inputs(psbt.inputs)

    def test_p2sh_p2wpkh_is_eligible(self):
        """The scriptPubKey check must not reject a legitimate P2SH-P2WPKH."""
        from embit.script import p2sh

        pub = _root().derive([0, 0]).get_public_key()
        redeem = p2wpkh(pub)
        psbt = self._p2sh_psbt(p2sh(redeem), redeem_script=redeem)

        self.assertEqual(get_eligible_inputs(psbt.inputs), [0])

    def test_lying_bip32_derivation_is_refused(self):
        """A PSBT that claims one of our derivations for an input we do not
        control must not contribute that key to a_sum.

        Both the derivation path and the pubkey it declares come from the PSBT,
        so they always agree with each other. Only the scriptPubKey, which comes
        from the UTXO, can expose the lie. Without that check the signer folds a
        key into a_sum that is absent from the real transaction, and the
        recipient can never find the resulting output.
        """
        root = _root()
        scan_pub, spend_pub = self._scan_spend()

        ours = root.derive([0, 0]).get_public_key()
        theirs = root.derive([9, 9]).get_public_key()

        psbt = PSBT.create_v2()

        inp = InputScope()
        inp.txid = bytes([0xC1] * 32)
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        # UTXO pays to a key we do not control ...
        inp.witness_utxo = TransactionOutput(
            value=100_000, script_pubkey=p2wpkh(theirs)
        )
        # ... but the PSBT claims the derivation of one we do.
        inp.bip32_derivations[ours] = DerivationPath(root.my_fingerprint, [0, 0])
        psbt.add_input(inp)

        out = OutputScope()
        out.value = 99_000
        out.sp_data = SilentPaymentData(scan_pub, spend_pub)
        psbt.add_output(out)

        self.assertIsNone(
            resolve_input_privkey(
                psbt.inputs[0], root, root.my_fingerprint, derive_hdkey
            )
        )
        with self.assertRaises(SPValidationError):
            psbt.sign_with(root)
        self.assertIsNone(psbt.outputs[0].script_pubkey)

    def test_honest_bip32_derivation_still_resolves(self):
        """The scriptPubKey binding must not reject a legitimate derivation."""
        root = _root()
        scan_pub, spend_pub = self._scan_spend()
        psbt, child = _make_p2wpkh_psbt(root, scan_pub, spend_pub)

        self.assertEqual(
            resolve_input_privkey(
                psbt.inputs[0], root, root.my_fingerprint, derive_hdkey
            ),
            child.key.secret,
        )

    def test_deriving_scripts_clears_modifiable_flags(self):
        """BIP-375: setting PSBT_OUT_SCRIPT must clear Inputs/Outputs Modifiable.

        Driven through derive_sp_outputs() rather than sign_with(), because the
        base signer clears the same flags as a side effect of adding a
        SIGHASH_ALL signature and would mask a broken mask here.
        """
        root = _root()
        scan_pub, spend_pub = self._scan_spend()
        psbt, _child = _make_p2wpkh_psbt(root, scan_pub, spend_pub)

        psbt.tx_modifiable_flags = (
            TxModifiable.INPUTS | TxModifiable.OUTPUTS | TxModifiable.SIGHASH_SINGLE
        )

        psbt.derive_sp_outputs(root)

        self.assertFalse(psbt.tx_modifiable_flags & TxModifiable.INPUTS)
        self.assertFalse(psbt.tx_modifiable_flags & TxModifiable.OUTPUTS)
        # Unrelated flags survive: BIP-375 names only Inputs/Outputs Modifiable.
        self.assertTrue(psbt.tx_modifiable_flags & TxModifiable.SIGHASH_SINGLE)

        # N1: the result must satisfy the validator the library itself applies.
        psbt.validate_sp()

        # The flags must still be a byte. Clearing them by assigning ~(I|O)
        # rather than masking yields -4, which passes every check above and
        # only fails here.
        self.assertEqual(psbt.tx_modifiable_flags, TxModifiable.SIGHASH_SINGLE)
        reparsed = PSBT.from_base64(psbt.to_base64())
        self.assertEqual(reparsed.tx_modifiable_flags, psbt.tx_modifiable_flags)
        reparsed.validate_sp()

    def test_derive_handles_absent_tx_modifiable(self):
        """A PSBT with no PSBT_GLOBAL_TX_MODIFIABLE (0x0b) must not crash."""
        root = _root()
        scan_pub, spend_pub = self._scan_spend()
        psbt, _child = _make_p2wpkh_psbt(root, scan_pub, spend_pub)

        psbt.tx_modifiable_flags = None

        psbt.derive_sp_outputs(root)

        self.assertIsNone(psbt.tx_modifiable_flags)
        psbt.validate_sp()
        PSBT.from_base64(psbt.to_base64()).validate_sp()

    def test_p2tr_input_produces_valid_sp_share(self):
        """A P2TR input we control yields an ECDH share + DLEQ proof that
        verify against the even-Y output key (BIP-352 taproot negation)."""
        root = _root()
        child = root.derive([0, 0])
        internal = child.get_public_key()
        out_priv = child.key.taproot_tweak(b"")  # even-Y output key
        scan_pub, spend_pub = self._scan_spend()

        psbt = PSBT.create_v2()

        inp = InputScope()
        inp.txid = bytes([0xAB] * 32)
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(
            value=100_000, script_pubkey=p2tr(internal)
        )
        inp.taproot_internal_key = internal
        inp.taproot_bip32_derivations[internal] = (
            [],
            DerivationPath(root.my_fingerprint, [0, 0]),
        )
        psbt.add_input(inp)

        out = OutputScope()
        out.value = 95_000
        out.sp_data = SilentPaymentData(scan_pub, spend_pub)
        psbt.add_output(out)

        self.assertEqual(psbt.sign_with(root), 1)

        sk = scan_pub.sec()
        share = psbt.sp_ecdh_shares.get(sk)
        proof = psbt.sp_dleq_proofs.get(sk)
        self.assertIsNotNone(share)
        # A is the even-Y output key taken from the scriptPubKey
        output_xonly = inp.script_pubkey.data[2:34]
        A = ec.PublicKey.from_xonly(bytes(output_xonly))
        self.assertEqual(A.xonly(), out_priv.xonly())
        self.assertTrue(dleq.verify_dleq_proof(A.sec(), sk, share, proof))

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
        out.sp_data = SilentPaymentData(scan_pub, spend_pub)
        psbt.add_output(out)

        with self.assertRaises(SPValidationError):
            psbt.sign_with(root)


class TestSignerBIP375Constraints(unittest.TestCase):
    """Signer-side BIP-375 constraints."""

    SCAN_HEX = "027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068"
    SPEND_HEX = "0361e1b1e9de5e42cb2007f7ca54b9e0d57ed13938fad56d3f19e57513a8fce039"

    def _psbt(self):
        root = _root()
        scan_pub, spend_pub = _sp_keys(self.SCAN_HEX, self.SPEND_HEX)
        return _make_p2wpkh_psbt(root, scan_pub, spend_pub)

    def test_non_sighash_all_rejected(self):
        """Signing SP outputs with a non-ALL sighash type must fail."""
        from embit.transaction import SIGHASH

        psbt, _ = self._psbt()
        with self.assertRaises(SPValidationError):
            psbt.sign_with(_root(), sighash=SIGHASH.SINGLE)


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

        psbt_a.sign_with(self.root, aux_rand=aux)
        psbt_b.sign_with(self.root, aux_rand=aux)

        proof_a = psbt_a.sp_dleq_proofs[self.scan_key_bytes]
        proof_b = psbt_b.sp_dleq_proofs[self.scan_key_bytes]
        self.assertEqual(proof_a, proof_b)


class TestSpendFromSP(unittest.TestCase):
    """BIP-376: spending a received Silent Payment UTXO via the sp_tweak field."""

    SCAN_HEX = "027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068"
    SPEND_HEX = "0361e1b1e9de5e42cb2007f7ca54b9e0d57ed13938fad56d3f19e57513a8fce039"

    @staticmethod
    def _odd_y_tweak(spend_priv):
        """A tweak whose tweaked spend key has odd Y, to exercise the negation."""
        for b in range(1, 256):
            t = bytes([b] * 32)
            if spend_priv.sp_spend_tweak(t).sec()[0] == 0x03:
                return t
        raise AssertionError("no odd-Y tweak found")

    def _input(self, root, tweak, output_xonly=None, fingerprint=None, value=100_000):
        """An SP-received P2TR input: output key P_k = B_spend + t*G, with the
        per-input sp_tweak and sp_spend_bip32_derivations a coordinator records."""
        child = root.derive([0, 0])
        spend_priv = child.key
        spend_pub = child.get_public_key()
        if output_xonly is None:
            output_xonly = spend_priv.sp_spend_tweak(tweak).xonly()
        fp = root.my_fingerprint if fingerprint is None else fingerprint
        inp = InputScope()
        inp.txid = bytes([0xCD] * 32)
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(
            value=value, script_pubkey=Script(b"\x51\x20" + output_xonly)
        )
        inp.sp_tweak = tweak
        inp.sp_spend_bip32_derivations[spend_pub.sec()] = DerivationPath(fp, [0, 0])
        return inp, spend_priv, spend_pub

    def _dest_psbt(self, root, inp):
        """PSBT with the SP-spend input and an ordinary P2WPKH destination."""
        psbt = PSBT.create_v2()
        psbt.add_input(inp)
        out = OutputScope()
        out.value = 95_000
        out.script_pubkey = p2wpkh(root.derive([1, 0]).get_public_key())
        psbt.add_output(out)
        return psbt

    def test_resolve_returns_even_y_tweaked_key(self):
        """_resolve_input_privkey returns the even-Y normalized b_spend + t."""
        root = _root()
        spend_priv = root.derive([0, 0]).key
        tweak = self._odd_y_tweak(spend_priv)  # force the negation path
        inp, _, _ = self._input(root, tweak)
        psbt = self._dest_psbt(root, inp)

        secret = resolve_input_privkey(
            psbt.inputs[0], root, root.my_fingerprint, derive_hdkey
        )
        self.assertIsNotNone(secret)
        expected = spend_priv.sp_spend_tweak(tweak).even_y()
        self.assertEqual(secret, expected.secret)
        self.assertEqual(expected.sec()[0], 0x02)  # even-Y
        self.assertEqual(
            expected.xonly(), bytes(inp.witness_utxo.script_pubkey.data[2:34])
        )

    def test_sign_produces_valid_signature(self):
        """_sign_sp_spends signs the input; the sig verifies against P_k."""
        from embit.transaction import SIGHASH

        root = _root()
        inp, _, _ = self._input(root, bytes([0x11] * 32))
        psbt = self._dest_psbt(root, inp)

        self.assertEqual(psbt._sign_sp_spends(root), 1)
        sig = psbt.inputs[0].taproot_key_sig
        self.assertIsNotNone(sig)
        self.assertEqual(len(sig), 64)

        output_xonly = bytes(psbt.inputs[0].witness_utxo.script_pubkey.data[2:34])
        msg = psbt.sighash(0, sighash=SIGHASH.DEFAULT)
        pub = ec.PublicKey.from_xonly(output_xonly)
        self.assertTrue(pub.schnorr_verify(ec.SchnorrSig(sig), msg))

    def test_declared_pubkey_parity_must_match(self):
        """BIP-376 keys the derivation map by the full 33-byte pubkey, so a
        declared key differing from ours only in the parity byte must not match."""
        root = _root()
        inp, _, _ = self._input(root, bytes([0x11] * 32))
        pub_bytes, derivation = next(iter(inp.sp_spend_bip32_derivations.items()))

        self.assertIsNotNone(
            match_sp_spend_base(inp, root, root.my_fingerprint, derive_hdkey)
        )

        del inp.sp_spend_bip32_derivations[pub_bytes]
        inp.sp_spend_bip32_derivations[bytes([pub_bytes[0] ^ 0x01]) + pub_bytes[1:]] = (
            derivation
        )
        self.assertIsNone(
            match_sp_spend_base(inp, root, root.my_fingerprint, derive_hdkey)
        )

    def test_raw_key_signs_only_controlled_inputs(self):
        """A raw (non-HD) key signs the SP-spend inputs it controls and skips
        the rest instead of failing the whole pass: unlike an HD signer it
        declares no derivation, so an uncontrolled input is not a corrupt PSBT."""
        root = _root()
        spend_priv = root.derive([0, 0]).key
        ours, _, _ = self._input(root, bytes([0x11] * 32))
        theirs, _, _ = self._input(
            root, bytes([0x22] * 32), output_xonly=bytes([0x55] * 32)
        )
        theirs.vout = 1  # distinct outpoint
        psbt = self._dest_psbt(root, ours)
        psbt.add_input(theirs)

        self.assertEqual(psbt._sign_sp_spends(spend_priv), 1)
        self.assertIsNotNone(psbt.inputs[0].taproot_key_sig)
        self.assertIsNone(psbt.inputs[1].taproot_key_sig)

    def test_foreign_tweak_not_signed(self):
        """A tweak that doesn't reproduce P_k yields no signature/key."""
        root = _root()
        spend_priv = root.derive([0, 0]).key
        onchain = spend_priv.sp_spend_tweak(bytes([0x11] * 32)).xonly()
        inp, _, _ = self._input(root, bytes([0x22] * 32), output_xonly=onchain)
        psbt = self._dest_psbt(root, inp)

        with self.assertRaises(SPValidationError):
            psbt._sign_sp_spends(root)
        self.assertIsNone(psbt.inputs[0].taproot_key_sig)
        self.assertIsNone(
            resolve_input_privkey(
                psbt.inputs[0], root, root.my_fingerprint, derive_hdkey
            )
        )

    def test_sign_honors_per_input_sighash_type(self):
        """An SP-spend input requesting SIGHASH_ALL must be signed with it.

        Under BIP-341 the hash type is part of the sighash message, so
        SIGHASH_DEFAULT (0x00) and SIGHASH_ALL (0x01) produce different digests
        and different encodings. Signing an ALL-requesting input with DEFAULT
        yields a signature that verifies against neither.
        """
        from embit.transaction import SIGHASH

        root = _root()
        inp, _, _ = self._input(root, bytes([0x11] * 32))
        inp.sighash_type = SIGHASH.ALL
        psbt = self._dest_psbt(root, inp)

        self.assertEqual(psbt._sign_sp_spends(root, sighash=None), 1)

        sig = psbt.inputs[0].taproot_key_sig
        self.assertIsNotNone(sig)
        # 64-byte sig + explicit hash type byte, per BIP-341.
        self.assertEqual(len(sig), 65)
        self.assertEqual(sig[-1], SIGHASH.ALL)

        output_xonly = bytes(psbt.inputs[0].witness_utxo.script_pubkey.data[2:34])
        pub = ec.PublicKey.from_xonly(output_xonly)
        self.assertTrue(
            pub.schnorr_verify(
                ec.SchnorrSig(sig[:64]), psbt.sighash(0, sighash=SIGHASH.ALL)
            )
        )
        # ... and specifically not over the DEFAULT digest.
        self.assertFalse(
            pub.schnorr_verify(
                ec.SchnorrSig(sig[:64]), psbt.sighash(0, sighash=SIGHASH.DEFAULT)
            )
        )

    def test_foreign_derivation_not_signed(self):
        """A derivation with a non-matching fingerprint is not signed."""
        root = _root()
        inp, _, _ = self._input(
            root, bytes([0x11] * 32), fingerprint=b"\xff\xff\xff\xff"
        )
        psbt = self._dest_psbt(root, inp)

        self.assertEqual(psbt._sign_sp_spends(root), 0)
        self.assertIsNone(psbt.inputs[0].taproot_key_sig)

    def _combined_psbt(self, root, inp):
        """PSBT with the SP-spend input and a (placeholder) SP output."""
        scan_pub, spend_pub_out = _sp_keys(self.SCAN_HEX, self.SPEND_HEX)
        psbt = PSBT.create_v2()
        psbt.add_input(inp)
        out = OutputScope()
        out.value = 95_000
        out.sp_data = SilentPaymentData(scan_pub, spend_pub_out)
        psbt.add_output(out)
        return psbt

    def test_input_sighash_eligibility(self):
        """Taproot SIGHASH_DEFAULT (0x00) is accepted as SIGHASH_ALL-equivalent;
        SIGHASH_ALL is accepted; other sighash types are rejected (BIP-375)."""
        from embit.transaction import SIGHASH

        root = _root()
        inp, _, _ = self._input(root, bytes([0x11] * 32))
        psbt = self._combined_psbt(root, inp)

        # Coordinators set 0x00 on taproot inputs; must not be rejected.
        psbt.inputs[0].sighash_type = SIGHASH.DEFAULT
        psbt.validate_sp()  # no raise

        psbt.inputs[0].sighash_type = SIGHASH.ALL
        psbt.validate_sp()  # no raise

        psbt.inputs[0].sighash_type = SIGHASH.NONE
        with self.assertRaises(SPValidationError):
            psbt.validate_sp()

    def test_self_transfer_share_verifies(self):
        """Combined: an SP-spend input contributes a valid SP share to a new SP
        output. Uses an odd-Y tweak so the even-Y negation is exercised, and the
        per-input DLEQ proof must verify against the even-Y output key A."""
        root = _root()
        spend_priv = root.derive([0, 0]).key
        tweak = self._odd_y_tweak(spend_priv)
        scan_pub, spend_pub_out = _sp_keys(self.SCAN_HEX, self.SPEND_HEX)

        inp, _, _ = self._input(root, tweak)
        psbt = PSBT.create_v2()
        psbt.add_input(inp)
        out = OutputScope()
        out.value = 95_000
        out.sp_data = SilentPaymentData(scan_pub, spend_pub_out)
        psbt.add_output(out)

        self.assertEqual(psbt.sign_with(root), 1)
        sk = scan_pub.sec()
        share = psbt.sp_ecdh_shares.get(sk)
        proof = psbt.sp_dleq_proofs.get(sk)
        self.assertIsNotNone(share)
        output_xonly = bytes(inp.witness_utxo.script_pubkey.data[2:34])
        A = ec.PublicKey.from_xonly(output_xonly)
        self.assertTrue(dleq.verify_dleq_proof(A.sec(), sk, share, proof))


class TestSPOutputTaprootInternalKey(unittest.TestCase):
    """
    A BIP-352 output key is the taproot output key itself - no BIP-341 tweak is
    applied - so there is no internal key to record. Writing
    PSBT_OUT_TAP_INTERNAL_KEY would assert script == OP_1 <tweak(P_k)>, which
    contradicts the script actually produced. BIP-375 does not ask for it.
    """

    SCAN_HEX = "027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068"
    SPEND_HEX = "0361e1b1e9de5e42cb2007f7ca54b9e0d57ed13938fad56d3f19e57513a8fce039"

    def _signed_psbt(self):
        root = _root()
        scan_pub, spend_pub = _sp_keys(self.SCAN_HEX, self.SPEND_HEX)
        psbt, _ = _make_p2wpkh_psbt(root, scan_pub, spend_pub)
        psbt.sign_with(root)
        return psbt

    def test_derive_does_not_set_internal_key(self):
        """derive_sp_outputs() leaves PSBT_OUT_TAP_INTERNAL_KEY unset."""
        out = self._signed_psbt().outputs[0]
        # SP output scriptPubKey is OP_1 PUSH32 <output key>
        output_xonly = out.script_pubkey.data[2:]
        self.assertEqual(len(output_xonly), 32)
        self.assertIsNone(out.taproot_internal_key)

    def test_output_key_is_not_taproot_tweaked(self):
        """The derived key is used raw, so tweaking it would change the script."""
        out = self._signed_psbt().outputs[0]
        output_xonly = out.script_pubkey.data[2:]
        internal = ec.PublicKey.from_xonly(output_xonly)
        # Had P_k been an internal key, the script would commit to tweak(P_k).
        self.assertNotEqual(internal.taproot_tweak(b"").xonly(), output_xonly)

    def test_clear_metadata_drops_sp_fields(self):
        """SP metadata is dropped and no internal key is resurrected."""
        out = self._signed_psbt().outputs[0]

        out.clear_metadata()

        self.assertIsNone(out.taproot_internal_key)
        self.assertIsNone(out.sp_data)
        self.assertIsNone(out.sp_label)

    def test_clear_metadata_drops_internal_key_on_non_sp_output(self):
        """Outputs without sp_data keep the base OutputScope behaviour."""
        root = _root()
        pub = root.derive([0, 0]).get_public_key()

        out = OutputScope()
        out.value = 10_000
        out.script_pubkey = p2tr(pub)
        out.taproot_internal_key = pub

        out.clear_metadata()

        self.assertIsNone(out.taproot_internal_key)


class TestP2SHRedeemScriptBinding(unittest.TestCase):
    """A P2SH redeem script is unauthenticated PSBT data until it hashes to
    the scriptPubKey, which is the only field the UTXO vouches for."""

    def _p2sh_input(self, root, script_pubkey):
        child = root.derive([0, 0])
        pub = child.get_public_key()

        inp = InputScope()
        inp.txid = bytes([0xB5] * 32)
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=script_pubkey)
        inp.redeem_script = p2wpkh(pub)
        inp.bip32_derivations[pub] = DerivationPath(root.my_fingerprint, [0, 0])
        return inp, child

    def test_honest_p2sh_p2wpkh_resolves(self):
        root = _root()
        inp, child = self._p2sh_input(
            root, p2sh(p2wpkh(root.derive([0, 0]).get_public_key()))
        )

        self.assertEqual(
            resolve_input_privkey(inp, root, root.my_fingerprint, derive_hdkey),
            child.key.secret,
        )

    def test_redeem_script_not_committed_by_scriptpubkey_is_refused(self):
        """Without the binding check a PSBT could point us at a key we own
        for an input we do not, silently corrupting a_sum."""
        root = _root()
        other = p2wpkh(root.derive([9, 9]).get_public_key())
        inp, _ = self._p2sh_input(root, p2sh(other))

        self.assertIsNone(
            resolve_input_privkey(inp, root, root.my_fingerprint, derive_hdkey)
        )
