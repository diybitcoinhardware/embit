"""Hash type negotiation around the unified opt-in digest.

The digest itself is covered by the cross-implementation vectors in
test_unified_sighash.py. Every defect found in this feature so far has been in the
code around it: which type is asked for, which is signed, which is refused, and what
a streaming reader caches while doing it. Each test here corresponds to one such
defect and fails against the code that had it.
"""
import io
from unittest import TestCase

from embit import script
from embit.bip32 import HDKey
from embit.psbt import PSBT, PSBTError, DerivationPath, InputScope, sighash_types_agree
from embit.psbtview import PSBTView
from embit.transaction import (
    SIGHASH,
    Transaction,
    TransactionError,
    TransactionInput,
    TransactionOutput,
)

ACP = SIGHASH.ANYONECANPAY

ROOT = HDKey.from_string(
    "tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA5"
    "6zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF"
)
U = SIGHASH.UNIFIED
UNIFIED_ALL = SIGHASH.UNIFIED | SIGHASH.ALL


def _wallet(kind):
    if kind == "taproot":
        pub = ROOT.derive("m/86h/1h/0h/0/0").to_public()
        return pub, script.p2tr(pub), 86
    pub = ROOT.derive("m/84h/1h/0h/0/0").to_public()
    return pub, script.p2wpkh(pub), 84


def build(declared, nout=1, kind="segwit", values=None):
    """A PSBT this root can sign, one input per declared hash type."""
    pub, spk, purpose = _wallet(kind)
    values = values or [100000 + i for i in range(len(declared))]
    vin = [
        TransactionInput(bytes(30) + i.to_bytes(2, "big"), 0)
        for i in range(len(declared))
    ]
    psbt = PSBT(
        Transaction(vin=vin, vout=[TransactionOutput(50000, spk) for _ in range(nout)])
    )
    for i, sh in enumerate(declared):
        inp = psbt.inputs[i]
        inp.witness_utxo = TransactionOutput(values[i], spk)
        derivation = DerivationPath(
            ROOT.my_fingerprint, [purpose + 2**31, 1 + 2**31, 2**31, 0, 0]
        )
        if kind == "taproot":
            inp.taproot_bip32_derivations[pub.key] = ([], derivation)
        else:
            inp.bip32_derivations[pub.key] = derivation
        inp.sighash_type = sh
    return psbt


def hash_type_bytes(psbt):
    out = []
    for inp in psbt.inputs:
        for sig in inp.partial_sigs.values():
            out.append(bytes(sig)[-1])
        for sig in taproot_signatures(inp):
            out.append(bytes(sig)[-1] if len(bytes(sig)) == 65 else SIGHASH.DEFAULT)
    return out


def taproot_signatures(inp):
    """Every taproot signature on an input, wherever this class keeps it.

    A script path spend goes to taproot_sigs. A key path spend goes to
    taproot_key_sig, or straight into the finalized witness where the class has no
    such field. Reading only one of them makes an assertion about a taproot hash
    type pass whether or not anything was signed.
    """
    sigs = list(inp.taproot_sigs.values())
    key_sig = getattr(inp, "taproot_key_sig", None)
    if key_sig is not None:
        return sigs + [key_sig]
    witness = getattr(inp, "final_scriptwitness", None)
    if witness is not None and witness.items:
        sigs.append(witness.items[0])
    return sigs


class TestSighashTypesAgree(TestCase):
    """The predicate deciding whether a declared type is the one being asked for.

    Ported from SighashTypesAgree in the reference implementation, with embit's own
    DEFAULT/ALL equivalence preserved for callers who never opt in.
    """

    def test_default_and_all_are_the_same_request(self):
        # embit has always folded these, and narrowing that would change behaviour
        # for callers who never touch the opt-in
        self.assertTrue(sighash_types_agree(SIGHASH.DEFAULT, SIGHASH.ALL))
        self.assertTrue(sighash_types_agree(SIGHASH.ALL, SIGHASH.DEFAULT))

    def test_different_output_types_disagree(self):
        self.assertFalse(sighash_types_agree(SIGHASH.NONE, SIGHASH.ALL))
        self.assertFalse(sighash_types_agree(SIGHASH.ALL, SIGHASH.NONE))
        self.assertFalse(sighash_types_agree(U | SIGHASH.NONE, UNIFIED_ALL))

    def test_the_opt_in_may_be_asked_for_over_a_legacy_declaration(self):
        # what every wallet predating the hardfork writes
        self.assertTrue(sighash_types_agree(SIGHASH.ALL, UNIFIED_ALL))
        self.assertTrue(sighash_types_agree(UNIFIED_ALL, SIGHASH.ALL))

    def test_a_bare_opt_in_is_not_default_or_all(self):
        """0x20 names no output type. Stripping the bit leaves zero, which is
        SIGHASH_DEFAULT's value but a different type carrying its own message, so it
        must not be folded in. The reference refuses to sign it."""
        self.assertFalse(sighash_types_agree(U, SIGHASH.ALL))
        self.assertFalse(sighash_types_agree(SIGHASH.ALL, U))
        self.assertFalse(sighash_types_agree(U, SIGHASH.DEFAULT))
        self.assertTrue(sighash_types_agree(U, U))

    def test_anyonecanpay_is_part_of_the_comparison(self):
        acp = SIGHASH.ANYONECANPAY
        self.assertTrue(sighash_types_agree(UNIFIED_ALL | acp, UNIFIED_ALL | acp))
        self.assertFalse(sighash_types_agree(UNIFIED_ALL | acp, UNIFIED_ALL))


class TestWhatGetsSigned(TestCase):
    def test_a_bare_opt_in_is_not_signed(self):
        """0x20 produced a signature whose hash type byte no verifier accepts."""
        for requested in (SIGHASH.DEFAULT, SIGHASH.ALL, UNIFIED_ALL):
            psbt = build([U])
            self.assertEqual(psbt.sign_with(ROOT, sighash=requested), 0)

    def test_the_opt_in_signs(self):
        psbt = build([UNIFIED_ALL, UNIFIED_ALL])
        self.assertEqual(psbt.sign_with(ROOT, sighash=UNIFIED_ALL), 2)
        self.assertEqual(hash_type_bytes(psbt), [UNIFIED_ALL, UNIFIED_ALL])

    def test_the_caller_gets_the_type_it_asked_for(self):
        """A PSBT declaring the legacy type, signed by a caller opting in."""
        psbt = build([SIGHASH.ALL])
        self.assertEqual(psbt.sign_with(ROOT, sighash=UNIFIED_ALL), 1)
        self.assertEqual(hash_type_bytes(psbt), [UNIFIED_ALL])

    def test_an_untouched_default_leaves_the_psbt_its_own_type(self):
        psbt = build([UNIFIED_ALL])
        self.assertEqual(psbt.sign_with(ROOT), 1)
        self.assertEqual(hash_type_bytes(psbt), [UNIFIED_ALL])


class TestTaprootRefusesABareOptIn(TestCase):
    """0x20 and 0xA0 name no output type. The bit cannot ride on SIGHASH_DEFAULT,
    which appends no byte to hold it, so on taproot they are types the reference
    refuses. Upgrading them to 0x21 signs something other than what was asked for,
    and did so silently on the one path that skips the agreement check."""

    def test_neither_class_signs_one(self):
        for declared in (U, U | ACP):
            for requested in (None, declared):
                psbt = build([declared], kind="taproot")
                self.assertEqual(
                    psbt.sign_with(ROOT, sighash=requested), 0,
                    f"0x{declared:02x} requested {requested}",
                )
                self.assertEqual(psbt.inputs[0].sighash_type, declared)

                view = PSBTView.view(io.BytesIO(build([declared], kind="taproot").serialize()),
                                     compress=False)
                self.assertEqual(
                    view.sign_input(0, ROOT, io.BytesIO(), sighash=requested), 0,
                    f"view 0x{declared:02x} requested {requested}",
                )

    def test_segwit_still_signs_one(self):
        """Bare and segwit v0 read the byte the legacy way, where 0x20 is a valid
        hash type carrying a message of its own. Refusing there would be wrong."""
        for declared in (U, U | ACP):
            psbt = build([declared])
            self.assertEqual(psbt.sign_with(ROOT, sighash=None), 1)
            self.assertEqual(hash_type_bytes(psbt), [declared])

    def test_a_sibling_is_still_signed(self):
        psbt = build([UNIFIED_ALL, U], kind="taproot")
        self.assertEqual(psbt.sign_with(ROOT, sighash=None), 1)
        self.assertEqual(hash_type_bytes(psbt), [UNIFIED_ALL])


class TestTheOptInIsTheOnlyThingOverridden(TestCase):
    """Naming a hash type gives the caller the last word over the algorithm, which
    is what the opt-in bit selects. Reaching further changes embit's own behaviour
    for callers who never touch the fork."""

    def test_taproot_default_signed_with_an_explicit_all_stays_default(self):
        psbt = build([SIGHASH.DEFAULT], kind="taproot")
        self.assertEqual(psbt.sign_with(ROOT, sighash=SIGHASH.ALL), 1)
        self.assertEqual(len(bytes(taproot_signatures(psbt.inputs[0])[0])), 64)
        self.assertEqual(hash_type_bytes(psbt), [SIGHASH.DEFAULT])

    def test_the_view_agrees(self):
        raw = build([SIGHASH.DEFAULT], kind="taproot").serialize()
        view = PSBTView.view(io.BytesIO(raw), compress=False)
        out = io.BytesIO()
        self.assertEqual(view.sign_input(0, ROOT, out, sighash=SIGHASH.ALL), 1)

        psbt = build([SIGHASH.DEFAULT], kind="taproot")
        psbt.sign_with(ROOT, sighash=SIGHASH.ALL)
        sig = bytes(taproot_signatures(psbt.inputs[0])[0])
        self.assertEqual(len(sig), 64)
        self.assertIn(sig, out.getvalue())

    def test_the_opt_in_is_still_overridden(self):
        psbt = build([SIGHASH.ALL])
        self.assertEqual(psbt.sign_with(ROOT, sighash=UNIFIED_ALL), 1)
        self.assertEqual(hash_type_bytes(psbt), [UNIFIED_ALL])


class TestTheFieldAgreesWithTheSignature(TestCase):
    """A finalizer reads the declared type. An input left advertising the opt-in
    beside a signature that does not carry it is a disagreement no reader can see
    through."""

    def test_a_caller_naming_a_plain_type_clears_the_declaration(self):
        for kind in ("segwit", "taproot"):
            psbt = build([UNIFIED_ALL], kind=kind)
            self.assertEqual(psbt.sign_with(ROOT, sighash=SIGHASH.ALL), 1)
            self.assertEqual(hash_type_bytes(psbt), [SIGHASH.ALL], kind)
            self.assertEqual(psbt.inputs[0].sighash_type, SIGHASH.ALL, kind)

    def test_signing_that_never_touches_the_opt_in_leaves_the_field_alone(self):
        psbt = build([None])
        self.assertEqual(psbt.sign_with(ROOT, sighash=SIGHASH.ALL), 1)
        self.assertIsNone(psbt.inputs[0].sighash_type)


class TestTheDigestMemoIsKeyed(TestCase):
    """Both classes memoize the hashes over the spent outputs. Keyed on nothing the
    memo is safe only while every caller passes the same list, and the unified digest
    is the first thing to take that list as an argument rather than read it off self."""

    def _tx(self):
        pub, spk, _ = _wallet("taproot")
        return Transaction(vin=[TransactionInput(bytes(32), 0)],
                           vout=[TransactionOutput(50000, spk)]), spk

    def test_transaction_recomputes_when_the_amounts_change(self):
        tx, spk = self._tx()
        tx.sighash_taproot(0, [spk], [100000])
        reused = tx.sighash_unified(0, 2, [spk], [999999], sighash=UNIFIED_ALL)
        fresh, _ = self._tx()
        self.assertEqual(
            reused, fresh.sighash_unified(0, 2, [spk], [999999], sighash=UNIFIED_ALL)
        )

    def test_transaction_recomputes_when_the_scripts_change(self):
        tx, spk = self._tx()
        other = _wallet("segwit")[1]
        tx.sighash_unified(0, 2, [spk], [100000], sighash=UNIFIED_ALL)
        reused = tx.sighash_unified(0, 2, [other], [100000], sighash=UNIFIED_ALL)
        fresh, _ = self._tx()
        self.assertEqual(
            reused, fresh.sighash_unified(0, 2, [other], [100000], sighash=UNIFIED_ALL)
        )

    def test_the_view_recomputes_when_the_scripts_change(self):
        """The amounts half of this was covered; the scripts half was not, so
        reverting its key broke nothing."""
        other = _wallet("taproot")[1]
        raw = build([UNIFIED_ALL], values=[100000]).serialize()

        view = PSBTView.view(io.BytesIO(raw), compress=False)
        view.sighash(0, sighash=UNIFIED_ALL)
        scope = view.input(0)
        scope.witness_utxo = TransactionOutput(100000, other)

        expected = build([UNIFIED_ALL], values=[100000])
        expected.inputs[0].witness_utxo = TransactionOutput(100000, other)
        self.assertEqual(view.sighash(0, sighash=UNIFIED_ALL, input_scope=scope),
                         expected.sighash(0, sighash=UNIFIED_ALL))


class TestSighashSingleWithNoOutput(TestCase):
    """SIGHASH_SINGLE commits to the output at the input's index. Where there is
    none the digest cannot be built, so that input is skipped as an unsignable one
    is, rather than discarding the signatures already made for the others."""

    def test_the_other_inputs_are_still_signed(self):
        for kind in ("segwit", "taproot"):
            psbt = build([UNIFIED_ALL, U | SIGHASH.SINGLE], nout=1, kind=kind)
            self.assertEqual(psbt.sign_with(ROOT, sighash=None), 1, kind)

    def test_the_streaming_reader_agrees(self):
        for kind in ("segwit", "taproot"):
            raw = build([UNIFIED_ALL, U | SIGHASH.SINGLE], nout=1, kind=kind).serialize()
            view = PSBTView.view(io.BytesIO(raw), compress=False)
            self.assertEqual(view.sign_with(ROOT, io.BytesIO(), sighash=None), 1, kind)

    def test_an_invalid_hash_type_is_still_an_error(self):
        """Skipping must be a check on this one condition, not a catch: an
        undefined type raises the same exception and must not be swallowed."""
        psbt = build([SIGHASH.ALL, 0x05])
        self.assertRaises(TransactionError, psbt.sign_with, ROOT, sighash=None)

    def test_the_legacy_digests_are_left_to_answer_it_themselves(self):
        """Without the opt-in this is not the unified message's problem. Segwit v0
        signs it, and skipping there would change behaviour for callers who never
        touch the fork."""
        psbt = build([SIGHASH.SINGLE], nout=0)
        self.assertEqual(psbt.sign_with(ROOT, sighash=None), 1)
        self.assertEqual(hash_type_bytes(psbt), [SIGHASH.SINGLE])

        raw = build([SIGHASH.SINGLE], nout=0).serialize()
        view = PSBTView.view(io.BytesIO(raw), compress=False)
        self.assertEqual(view.sign_with(ROOT, io.BytesIO(), sighash=None), 1)

    def test_the_opt_in_is_still_skipped(self):
        psbt = build([U | SIGHASH.SINGLE], nout=0)
        self.assertEqual(psbt.sign_with(ROOT, sighash=None), 0)


class TestPrevoutIndex(TestCase):
    """The index selecting from the previous transaction comes off the wire."""

    def _psbt_with_bad_index(self, vout):
        pub, spk, _ = _wallet("segwit")
        prev = Transaction(
            vin=[TransactionInput(bytes(32), 0)], vout=[TransactionOutput(100000, spk)]
        )
        psbt = build([UNIFIED_ALL, UNIFIED_ALL])
        psbt.inputs[1].witness_utxo = None
        psbt.inputs[1].non_witness_utxo = prev
        psbt.inputs[1].vout = vout
        return psbt

    def test_an_index_past_the_end_is_reported_not_raised(self):
        psbt = self._psbt_with_bad_index(5)
        self.assertRaises(PSBTError, psbt.sighash, 0, sighash=UNIFIED_ALL)
        self.assertRaises(PSBTError, psbt.sign_with, ROOT, sighash=UNIFIED_ALL)

    def test_a_missing_index_is_reported_not_raised(self):
        psbt = self._psbt_with_bad_index(None)
        self.assertRaises(PSBTError, psbt.sighash, 0, sighash=UNIFIED_ALL)

    def test_the_scope_reports_it_too(self):
        """InputScope.utxo carries its own copy of these checks, and only PSBT.utxo's
        was reached from here."""
        for vout in (5, None):
            inp = self._psbt_with_bad_index(vout).inputs[1]
            with self.assertRaises(PSBTError):
                inp.utxo


class TestStreamingReaderCache(TestCase):
    """PSBTView caches the spent outputs it reads, because the unified digest needs
    every one of them and re-reading is quadratic. A cache on a streaming reader is
    where a stale or borrowed value silently produces a wrong digest."""

    def test_a_caller_supplied_utxo_does_not_leak_into_siblings(self):
        """Signing one input with a utxo supplied out of band must not hand that
        value to any other input as its sibling amount.

        ANYONECANPAY carries only the signed input's spent output, so it is the one
        message a caller may legitimately build from a value the PSBT contradicts.
        What the sibling reads afterwards is the whole question here.
        """
        psbt = build([UNIFIED_ALL | ACP, UNIFIED_ALL], values=[100000, 200000])
        raw = psbt.serialize()
        pub, spk, _ = _wallet("segwit")
        supplied = InputScope()
        supplied.witness_utxo = TransactionOutput(999999, spk)

        view = PSBTView.view(io.BytesIO(raw), compress=False)
        view.sign_input(0, ROOT, io.BytesIO(), sighash=UNIFIED_ALL | ACP,
                        extra_scope_data=supplied)

        self.assertEqual(view.sighash(1, sighash=UNIFIED_ALL),
                         psbt.sighash(1, sighash=UNIFIED_ALL))

    def test_a_supplied_utxo_the_psbt_contradicts_is_refused(self):
        """The siblings would still be the stream's, so the two signatures would
        commit to different spent output vectors and nothing would say which."""
        psbt = build([UNIFIED_ALL, UNIFIED_ALL], values=[100000, 200000])
        raw = psbt.serialize()
        pub, spk, _ = _wallet("segwit")
        supplied = InputScope()
        supplied.witness_utxo = TransactionOutput(999999, spk)

        view = PSBTView.view(io.BytesIO(raw), compress=False)
        self.assertRaises(PSBTError, view.sighash, 0, sighash=UNIFIED_ALL,
                          input_scope=supplied)
        self.assertRaises(PSBTError, view.sign_input, 0, ROOT, io.BytesIO(),
                          sighash=UNIFIED_ALL, extra_scope_data=supplied)

    def test_a_reused_view_still_honours_a_supplied_utxo(self):
        """The digest memo was keyed on nothing, so the first call's answer came
        back for every later one. One input has no sibling to disagree with, so a
        caller that knows better than the PSBT is free to say so."""
        pub, spk, _ = _wallet("segwit")
        raw = build([UNIFIED_ALL], values=[100000]).serialize()
        view = PSBTView.view(io.BytesIO(raw), compress=False)
        self.assertEqual(view.sighash(0, sighash=UNIFIED_ALL),
                         build([UNIFIED_ALL], values=[100000]).sighash(0, sighash=UNIFIED_ALL))

        scope = view.input(0)
        scope.witness_utxo = TransactionOutput(777777, spk)
        self.assertEqual(view.sighash(0, sighash=UNIFIED_ALL, input_scope=scope),
                         build([UNIFIED_ALL], values=[777777]).sighash(0, sighash=UNIFIED_ALL))

    def test_signing_works_when_the_utxo_is_supplied_out_of_band(self):
        """PSBTView exists for signers that know more than the PSBT carries."""
        pub, spk, _ = _wallet("segwit")
        psbt = build([UNIFIED_ALL])
        psbt.inputs[0].witness_utxo = None
        raw = psbt.serialize()
        supplied = InputScope()
        supplied.witness_utxo = TransactionOutput(100000, spk)

        view = PSBTView.view(io.BytesIO(raw), compress=False)
        self.assertEqual(
            view.sign_input(0, ROOT, io.BytesIO(), sighash=UNIFIED_ALL,
                            extra_scope_data=supplied),
            1,
        )

    def test_a_supplied_value_is_not_cached_for_later_inputs(self):
        """A value supplied for one input is not the stream's. Caching the aggregate
        it produced would let a later input borrow it, so whether that input can be
        signed at all would depend on which one was signed first."""
        psbt = build([UNIFIED_ALL, UNIFIED_ALL], values=[100000, 200000])
        pub, spk, _ = _wallet("segwit")
        psbt.inputs[0].witness_utxo = None
        raw = psbt.serialize()
        supplied = InputScope()
        supplied.witness_utxo = TransactionOutput(100000, spk)

        view = PSBTView.view(io.BytesIO(raw), compress=False)
        view.sighash(0, sighash=UNIFIED_ALL, input_scope=supplied)
        # input 0 is still missing as far as the PSBT is concerned
        self.assertRaises(PSBTError, view.sighash, 1, sighash=UNIFIED_ALL)

        # and the order the caller happened to use does not change that
        fresh = PSBTView.view(io.BytesIO(raw), compress=False)
        self.assertRaises(PSBTError, fresh.sighash, 1, sighash=UNIFIED_ALL)

    def test_a_missing_sibling_is_reported_not_dereferenced(self):
        """The digest needs every spent output. One the PSBT does not carry is a
        PSBTError naming the input, not an AttributeError from inside the digest."""
        psbt = build([UNIFIED_ALL, UNIFIED_ALL])
        psbt.inputs[1].witness_utxo = None
        view = PSBTView.view(io.BytesIO(psbt.serialize()), compress=False)
        with self.assertRaises(PSBTError) as caught:
            view.sighash(0, sighash=UNIFIED_ALL)
        self.assertIn("input 1", str(caught.exception))

    def test_what_is_kept_does_not_grow_with_the_transaction(self):
        """The reason this class exists. The digest commits to every spent output, but
        only the two aggregates over them are kept, so a signer that cannot hold the
        whole transaction still does not have to."""
        kept = []
        for n in (2, 40, 200):
            raw = build([UNIFIED_ALL] * n, nout=1).serialize()
            view = PSBTView.view(io.BytesIO(raw), compress=False)
            view.sighash(0, sighash=UNIFIED_ALL)
            cache = view._spent_output_hashes_cache
            self.assertEqual(len(cache), 2, n)
            kept.append(sum(len(x) for x in cache))
        self.assertEqual(kept, [64, 64, 64])

    def test_anyonecanpay_keeps_nothing_and_reads_no_sibling(self):
        """It commits to this input's spent output alone, so requiring the siblings
        would refuse PSBTs the algorithm does not need them for."""
        psbt = build([UNIFIED_ALL | ACP, UNIFIED_ALL | ACP], values=[100000, 200000])
        psbt.inputs[1].witness_utxo = None
        view = PSBTView.view(io.BytesIO(psbt.serialize()), compress=False)
        self.assertEqual(view.sign_input(0, ROOT, io.BytesIO(), sighash=UNIFIED_ALL | ACP), 1)
        self.assertIsNone(view._spent_output_hashes_cache)

    def test_caching_does_not_change_any_digest(self):
        """Signing several inputs on one view must equal a fresh view per input."""
        for kind in ("segwit", "taproot"):
            for declared in (UNIFIED_ALL, U | SIGHASH.NONE, UNIFIED_ALL | SIGHASH.ANYONECANPAY):
                psbt = build([declared] * 3, nout=3, kind=kind)
                raw = psbt.serialize()
                shared = PSBTView.view(io.BytesIO(raw), compress=False)
                for i in range(3):
                    fresh = PSBTView.view(io.BytesIO(raw), compress=False)
                    self.assertEqual(
                        shared.sighash(i, sighash=declared),
                        fresh.sighash(i, sighash=declared),
                        f"{kind} 0x{declared:02x} input {i}",
                    )


class TestClassesAgree(TestCase):
    """PSBT and PSBTView must produce the same digest. A defect in one and not the
    other is how a signer and its verifier come to disagree."""

    def test_digests_match_across_hash_types_and_shapes(self):
        types = [
            UNIFIED_ALL,
            U | SIGHASH.NONE,
            U | SIGHASH.SINGLE,
            UNIFIED_ALL | SIGHASH.ANYONECANPAY,
            SIGHASH.ALL,
        ]
        for kind in ("segwit", "taproot"):
            for n in (1, 2, 3):
                for nout in (1, 3):
                    for declared in types:
                        psbt = build([declared] * n, nout=nout, kind=kind)
                        raw = psbt.serialize()
                        for i in range(n):
                            view = PSBTView.view(io.BytesIO(raw), compress=False)
                            try:
                                expected = psbt.sighash(i, sighash=declared)
                            except (PSBTError, TransactionError) as e:
                                self.assertRaises(
                                    type(e), view.sighash, i, sighash=declared
                                )
                                continue
                            self.assertEqual(
                                expected,
                                view.sighash(i, sighash=declared),
                                f"{kind} n={n} nout={nout} 0x{declared:02x} input {i}",
                            )
