from io import BytesIO

import pytest

from embit import ec, script
from embit.psbt import PSBT, PSBTError, CompressMode, InputScope
from embit.psbtview import PSBTView
from embit.transaction import (
    SIGHASH,
    Transaction,
    TransactionInput,
    TransactionOutput,
)


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


@pytest.mark.parametrize("version", [None, 2])
@pytest.mark.parametrize(
    "compress", [CompressMode.KEEP_ALL, CompressMode.CLEAR_ALL, CompressMode.PARTIAL]
)
@pytest.mark.parametrize("conflict", [None, "amount", "script"])
def test_verify_checks_both_utxo_representations(version, compress, conflict):
    psbt, key = funded_psbt(version)
    if conflict == "amount":
        psbt.inputs[0].witness_utxo.value = 1000
    elif conflict == "script":
        psbt.inputs[0].witness_utxo.script_pubkey = script.Script(b"\x51")
    raw = psbt.serialize()
    parsed = PSBT.parse(raw, compress=compress)
    viewed = PSBTView.view(BytesIO(raw), compress=compress).input(0)
    if conflict:
        for inp in (parsed.inputs[0], viewed):
            with pytest.raises(PSBTError, match="Witness utxo doesn't match"):
                inp.verify()
            assert not inp.is_verified
    else:
        assert parsed.verify()
        assert viewed.verify()
        assert parsed.fee() == 1000
        assert parsed.sign_with(key) == 1
        signature = parsed.inputs[0].partial_sigs[key.get_public_key()]
        assert key.verify(ec.Signature.parse(signature[:-1]), psbt.sighash(0))


@pytest.mark.parametrize("version", [None, 2])
@pytest.mark.parametrize(
    "compress", [CompressMode.KEEP_ALL, CompressMode.CLEAR_ALL, CompressMode.PARTIAL]
)
def test_view_signs_the_taproot_amounts_it_shows(version, compress):
    key = ec.PrivateKey((1).to_bytes(32, "big"))
    spk = script.p2tr(key.get_public_key())
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
    # unverified witness utxo understating the amount
    psbt.inputs[0].witness_utxo = TransactionOutput(1000, spk)
    raw = psbt.serialize()
    view = PSBTView.view(BytesIO(raw), compress=compress)
    shown = view.input(0).utxo
    expected = psbt.tx.sighash_taproot(
        0, [shown.script_pubkey], [shown.value], sighash=SIGHASH.DEFAULT
    )
    assert view.sighash(0, sighash=SIGHASH.DEFAULT) == expected
    parsed = PSBT.parse(raw, compress=compress)
    assert parsed.sighash(0, sighash=SIGHASH.DEFAULT) == expected


def test_failed_reverification_clears_verified_state():
    psbt, _ = funded_psbt(None)
    inp = psbt.inputs[0]
    assert inp.verify()
    inp.witness_utxo.value = 1
    with pytest.raises(PSBTError):
        inp.verify()
    assert not inp.is_verified


@pytest.mark.parametrize("index", [-1, 1, None])
def test_verify_rejects_invalid_non_witness_output_index(index):
    psbt, _ = funded_psbt(None)
    psbt.inputs[0].vout = index
    with pytest.raises(PSBTError, match="output index"):
        psbt.verify()
    assert not psbt.is_verified


def test_update_with_utxo_data_clears_verified_state():
    psbt, _ = funded_psbt(None)
    inp = psbt.inputs[0]
    inp.witness_utxo = None
    assert psbt.verify()
    # merging signatures keeps the verification
    other = InputScope()
    other.partial_sigs[b"pub"] = b"sig"
    inp.update(other)
    assert inp.is_verified
    other = InputScope()
    other.witness_utxo = TransactionOutput(1000000, inp.utxo.script_pubkey)
    inp.update(other)
    assert not inp.is_verified
    with pytest.raises(PSBTError, match="Witness utxo doesn't match"):
        psbt.verify()


@pytest.mark.parametrize("compress", [CompressMode.CLEAR_ALL, CompressMode.PARTIAL])
def test_update_keeps_compressed_utxo_with_its_txhash(compress):
    psbt, _ = funded_psbt(None)
    psbt.inputs[0].witness_utxo = None
    spk = psbt.inputs[0].non_witness_utxo.vout[0].script_pubkey
    good = PSBT.parse(psbt.serialize(), compress=compress)
    assert good.verify()
    # unrelated previous transaction with an inflated amount
    psbt.inputs[0].non_witness_utxo = Transaction(
        vin=[TransactionInput(b"\x07" * 32, 0)],
        vout=[TransactionOutput(1000000, spk)],
    )
    evil = PSBT.parse(psbt.serialize(), compress=compress)
    good.inputs[0].update(evil.inputs[0])
    assert not good.is_verified
    with pytest.raises(PSBTError, match="txid doesn't match"):
        good.verify()
    assert not good.is_verified


def two_output_psbt(version):
    psbt, key = funded_psbt(version)
    spk = script.p2pkh(key.get_public_key())
    previous = psbt.inputs[0].non_witness_utxo
    previous.vout = [TransactionOutput(10000, spk), TransactionOutput(1000000, spk)]
    psbt.inputs[0].txid = previous.txid()
    psbt.inputs[0].witness_utxo = None
    return psbt, key


@pytest.mark.parametrize("version", [None, 2])
@pytest.mark.parametrize("compress", [CompressMode.CLEAR_ALL, CompressMode.PARTIAL])
@pytest.mark.parametrize("replacement", [None, "full", "compressed"])
def test_update_output_index_cannot_reuse_cached_amount(version, compress, replacement):
    original, key = two_output_psbt(version)
    previous = original.inputs[0].non_witness_utxo
    psbt = PSBT.parse(original.serialize(), compress=compress)
    assert psbt.verify()
    assert psbt.fee() == 1000
    other = InputScope()
    other.vout = 1
    if replacement == "full":
        other.non_witness_utxo = previous
    elif replacement == "compressed":
        original.inputs[0].vout = 1
        other = PSBT.parse(original.serialize(), compress=compress).inputs[0]
    psbt.inputs[0].update(other)
    assert not psbt.is_verified
    if replacement is None:
        with pytest.raises(PSBTError, match="Missing non_witness_utxo"):
            psbt.verify()
        assert not psbt.is_verified
        assert psbt.inputs[0].utxo is None
        with pytest.raises(PSBTError, match="Missing previous utxo"):
            psbt.sign_with(key)
        # Supplying the full previous transaction recovers the correct output.
        other.non_witness_utxo = previous
        psbt.inputs[0].update(other)
    assert psbt.verify()
    assert psbt.inputs[0].utxo.value == 1000000
    assert psbt.fee() == 991000
    assert psbt.sign_with(key) == 1
    actual = PSBT(psbt.tx)
    actual.inputs[0].non_witness_utxo = previous
    signature = psbt.inputs[0].partial_sigs[key.get_public_key()]
    assert key.verify(ec.Signature.parse(signature[:-1]), actual.sighash(0))


@pytest.mark.parametrize("version", [None, 2])
@pytest.mark.parametrize("compress", [CompressMode.CLEAR_ALL, CompressMode.PARTIAL])
def test_update_unchanged_prevout_keeps_usable_cache(version, compress):
    original, _ = two_output_psbt(version)
    psbt = PSBT.parse(original.serialize(), compress=compress)
    assert psbt.verify()
    psbt.inputs[0].update(InputScope(vin=psbt.inputs[0].vin))
    assert not psbt.is_verified
    assert psbt.verify()
    assert psbt.fee() == 1000


@pytest.mark.parametrize("version", [None, 2])
@pytest.mark.parametrize("compress", [CompressMode.CLEAR_ALL, CompressMode.PARTIAL])
def test_update_rejects_incoming_cache_with_changed_index(version, compress):
    original, _ = two_output_psbt(version)
    incoming = PSBT.parse(original.serialize(), compress=compress).inputs[0]
    incoming.vout = 1
    original.inputs[0].update(incoming)
    with pytest.raises(PSBTError, match="Cached utxo doesn't match output index"):
        original.verify()
    assert not original.is_verified


@pytest.mark.parametrize("compress", [CompressMode.CLEAR_ALL, CompressMode.PARTIAL])
def test_update_full_transaction_replaces_old_cached_hash(compress):
    original, _ = two_output_psbt(None)
    psbt = PSBT.parse(original.serialize(), compress=compress)
    assert psbt.verify()
    previous = original.inputs[0].non_witness_utxo
    previous.vout[0].value = 20000
    original.inputs[0].txid = previous.txid()
    psbt.inputs[0].update(original.inputs[0])
    assert not psbt.is_verified
    assert psbt.verify()
    assert psbt.fee() == 11000


@pytest.mark.parametrize("compress", [CompressMode.CLEAR_ALL, CompressMode.PARTIAL])
def test_update_full_transaction_is_not_shadowed_by_cache(compress):
    original, _ = two_output_psbt(None)
    psbt = PSBT.parse(original.serialize(), compress=compress)
    assert psbt.verify()
    other = InputScope()
    other.non_witness_utxo = Transaction(
        vin=[TransactionInput(b"\x07" * 32, 0)],
        vout=[TransactionOutput(5, original.inputs[0].utxo.script_pubkey)],
    )
    psbt.inputs[0].update(other)
    with pytest.raises(PSBTError, match="txid doesn't match"):
        psbt.verify()
    assert not psbt.is_verified


@pytest.mark.parametrize("compress", [CompressMode.CLEAR_ALL, CompressMode.PARTIAL])
@pytest.mark.parametrize("witness_utxo", [False, True])
def test_update_from_compressed_scope_drops_other_full_transaction(
    compress, witness_utxo
):
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
        Transaction(vin=[TransactionInput(previous.txid(), 0)], vout=psbt.tx.vout)
    )
    replacement.inputs[0].non_witness_utxo = previous
    if witness_utxo:
        replacement.inputs[0].witness_utxo = previous.vout[0]
    incoming = PSBT.parse(replacement.serialize(), compress=compress).inputs[0]
    assert incoming.non_witness_utxo is None
    psbt.inputs[0].update(incoming)
    assert psbt.verify()
    assert psbt.fee() == 11000
    # the transaction the cache was not streamed from is not written back
    assert psbt.inputs[0].non_witness_utxo is None
    reparsed = PSBT.parse(psbt.serialize())
    assert reparsed.inputs[0].txid == previous.txid()
    assert reparsed.inputs[0].non_witness_utxo is None
    assert not reparsed.verify(ignore_missing=True)


@pytest.mark.parametrize("compress", [CompressMode.CLEAR_ALL, CompressMode.PARTIAL])
def test_update_from_compressed_scope_keeps_its_full_transaction(compress):
    psbt, _ = funded_psbt(None)
    previous = psbt.inputs[0].non_witness_utxo
    incoming = PSBT.parse(psbt.serialize(), compress=compress).inputs[0]
    psbt.inputs[0].update(incoming)
    assert psbt.inputs[0].non_witness_utxo is previous
    assert psbt.verify()
    assert PSBT.parse(psbt.serialize()).verify()
