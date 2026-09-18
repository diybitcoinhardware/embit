"""Defensive checks for complete fields and nested transaction framing."""

from binascii import a2b_base64
from hashlib import sha256
from io import BytesIO
from unittest import TestCase

from embit import compact
from embit.base import EmbitError
from embit.psbt import CompressMode, InputScope, PSBT, PSBTError
from embit.psbtview import GlobalTransactionView, PSBTView
from embit.script import Script, Witness
from embit.transaction import (
    Transaction,
    TransactionError,
    TransactionInput,
    TransactionOutput,
)
from .test_psbtview import PSBTS


class SequentialStream:
    """Read-only stream, optionally returning a short result at a field offset."""

    def __init__(self, data, short_at=None):
        self.source = BytesIO(data)
        self.short_at = short_at
        self.max_read = 0
        self.bytes_read = 0

    def read(self, size):
        self.max_read = max(size, self.max_read)
        if self.source.seek(0, 1) == self.short_at and size:
            size -= 1
        data = self.source.read(size)
        self.bytes_read += len(data)
        return data


class TrackingStream(SequentialStream):
    def seek(self, offset, whence=0):
        return self.source.seek(offset, whence)

    def tell(self):
        return self.source.seek(0, 1)


class ParsingTest(TestCase):
    def transaction(self, locktime=0):
        return Transaction(
            vin=[TransactionInput(bytes(range(32)), 1)],
            vout=[TransactionOutput(42, Script(b""))],
            locktime=locktime,
        )

    def global_psbt(self, raw):
        return b"psbt\xff\x01\x00" + compact.to_bytes(len(raw)) + raw + b"\x00\x00\x00"

    def test_fixed_fields(self):
        raw = self.transaction().serialize()
        # Version, input txid, output index, sequence, output value, locktime.
        for offset, width in [(0, 4), (5, 32), (37, 4), (42, 4), (47, 8), (56, 4)]:
            for reader in (
                Transaction.read_from,
                lambda s: Transaction.read_vout(s, 0),
            ):
                with self.assertRaises(TransactionError):
                    reader(SequentialStream(raw, offset))
                for count in range(width):
                    with self.assertRaises(TransactionError):
                        reader(BytesIO(raw[: offset + count]))
        for reader, raw_field in (
            (TransactionInput.read_from, self.transaction().vin[0].serialize()),
            (TransactionOutput.read_from, self.transaction().vout[0].serialize()),
        ):
            with self.assertRaises(TransactionError):
                reader(SequentialStream(raw_field, 0))

    def test_locktime_and_stream_consumption(self):
        for locktime in (0, 1, 255, 256, 0xFFFFFFFF):
            tx = self.transaction(locktime)
            raw = tx.serialize()
            self.assertEqual(Transaction.parse(raw).serialize(), raw)
            expected_hash = sha256(sha256(raw).digest()).digest()
            self.assertEqual(tx.hash(), expected_hash)
            for reader in (
                Transaction.read_from,
                lambda s: Transaction.read_vout(s, 0),
            ):
                stream = BytesIO(raw + b"next")
                reader(stream)
                self.assertEqual(stream.read(), b"next")
                for missing in (1, 2, 3, 4):
                    with self.assertRaises(TransactionError):
                        reader(BytesIO(raw[:-missing]))
            with self.assertRaises(EmbitError):
                Transaction.parse(raw + b"next")
            output, txhash = Transaction.read_vout(BytesIO(raw), 0)
            self.assertEqual(output.serialize(), tx.vout[0].serialize())
            self.assertEqual(txhash, expected_hash)

    def test_compact(self):
        with self.assertRaises(RuntimeError):
            compact.read_from(BytesIO(b""))
        for prefix, width in ((253, 2), (254, 4), (255, 8)):
            raw = bytes([prefix]) + b"\x01" + bytes(width - 1)
            self.assertEqual(compact.from_bytes(raw), 1)  # Minimality is unchanged.
            for count in range(width):
                with self.assertRaises(RuntimeError):
                    compact.from_bytes(raw[: 1 + count])
            with self.assertRaises(RuntimeError):
                compact.read_from(SequentialStream(raw, 1))
        for value in (0, 252, 253, 65535, 65536, 0xFFFFFFFF, 0x100000000):
            self.assertEqual(compact.from_bytes(compact.to_bytes(value)), value)

    def test_witness(self):
        for items in ([], [b""], [b"", b"abc", b""]):
            raw = Witness(items).serialize()
            self.assertEqual(Witness.parse(raw).items, items)
        with self.assertRaises(ValueError):
            Witness.parse(b"\x02\x00\x03ab")
        with self.assertRaises(ValueError):
            Witness.read_from(SequentialStream(b"\x01\x03abc", 2))
        tx = self.transaction()
        tx.vin[0].witness = Witness([b"abc"])
        raw = tx.serialize()
        self.assertEqual(Transaction.parse(raw).serialize(), raw)
        for reader in (Transaction.read_from, lambda s: Transaction.read_vout(s, 0)):
            with self.assertRaises(ValueError):
                reader(BytesIO(raw[:-5]))
        self.assertEqual(Transaction.read_vout(BytesIO(raw), 0)[1], tx.hash())

    def test_existing_fixture(self):
        psbt = PSBT.from_string(PSBTS[0])
        raw = psbt.tx.serialize()
        self.assertEqual(Transaction.parse(raw).serialize(), raw)
        view = PSBTView.view(BytesIO(a2b_base64(PSBTS[0])))
        for i, output in enumerate(psbt.tx.vout):
            parsed, txhash = Transaction.read_vout(BytesIO(raw), i)
            self.assertEqual(parsed.serialize(), output.serialize())
            self.assertEqual(txhash, sha256(sha256(raw).digest()).digest())
            self.assertEqual(view.tx.vout(i).serialize(), output.serialize())

    def test_non_witness_boundary(self):
        tx = self.transaction()
        raw = tx.serialize()
        following = b"\x01\x03\x04\x01\x00\x00\x00\x00"
        for mode in (
            CompressMode.KEEP_ALL,
            CompressMode.CLEAR_ALL,
            CompressMode.PARTIAL,
        ):
            vin = TransactionInput(tx.txid(), 0)
            scope = InputScope(vin=vin, compress=mode)
            stream = SequentialStream(compact.to_bytes(len(raw)) + raw + following)
            scope.read_value(stream, b"\x00")
            self.assertEqual(stream.read(len(following)), following)
            if mode:
                self.assertEqual(scope._utxo.serialize(), tx.vout[0].serialize())
                self.assertEqual(scope._txhash, tx.hash())
            else:
                self.assertEqual(scope.non_witness_utxo.serialize(), raw)
            for value, length in (
                (raw, len(raw) - 1),
                (raw + b"x", len(raw) + 1),
                (raw[:-1], len(raw)),
            ):
                scope = InputScope(vin=vin, compress=mode)
                stream = SequentialStream(compact.to_bytes(length) + value)
                with self.assertRaises(PSBTError):
                    scope.read_value(stream, b"\x00")
                self.assertEqual(scope.non_witness_utxo, None)
                self.assertEqual(scope._utxo, None)
                self.assertEqual(scope._txhash, None)
            scope = InputScope(vin=vin, compress=mode)
            stream = SequentialStream(compact.to_bytes(len(raw) - 1) + raw + following)
            with self.assertRaises(PSBTError):
                scope.read_value(stream, b"\x00")
            self.assertTrue(
                stream.source.seek(0, 1)
                <= len(compact.to_bytes(len(raw))) + len(raw) - 1
            )

    def test_global_boundaries(self):
        raw = self.transaction().serialize()
        for value in (raw[:-1], raw[:-4], raw + b"x"):
            payload = self.global_psbt(value)
            with self.assertRaises(EmbitError):
                PSBT.parse(payload)
            with self.assertRaises(PSBTError):
                PSBTView.view(BytesIO(payload))
        with self.assertRaises(PSBTError):
            PSBT.parse(self.global_psbt(raw)[:20])
        with self.assertRaises(PSBTError):
            PSBTView.view(BytesIO(self.global_psbt(raw)[:20]))
        prefix = b"prefix"
        stream = BytesIO(prefix + self.global_psbt(raw))
        stream.seek(len(prefix))
        view = PSBTView.view(stream, offset=len(prefix))
        self.assertEqual(view.tx.version, 2)
        self.assertEqual(view.tx.locktime, 0)
        self.assertEqual(
            view.tx.vin(0).serialize(), self.transaction().vin[0].serialize()
        )
        self.assertEqual(view.tx.vout(0).value, 42)
        view.seek_to_scope(2)
        self.assertEqual(stream.read(), b"")

    def test_direct_views(self):
        raw = self.transaction().serialize()
        for length in (None, len(raw)):
            view = GlobalTransactionView(BytesIO(raw), 0, length)
            self.assertEqual(view.locktime, 0)
            self.assertEqual(view.version, 2)
            self.assertEqual(view.vout(0).value, 42)
        with self.assertRaises(TransactionError):
            _ = GlobalTransactionView(BytesIO(b"\x02"), 0).version
        with self.assertRaises(TransactionError):
            _ = GlobalTransactionView(BytesIO(raw[:-1]), 0).locktime
        for offset, width in ((0, 4), (5, 32), (37, 4), (42, 4), (47, 8), (56, 4)):
            view = GlobalTransactionView(BytesIO(raw), 0, offset + width - 1)
            with self.assertRaises(PSBTError):
                if offset == 0:
                    _ = view.version
                elif offset < 47:
                    view.vin(0)
                elif offset == 47:
                    view.vout(0)
                else:
                    _ = view.locktime
        # Truncated CompactSize count cannot read into a following map.
        with self.assertRaises(PSBTError):
            _ = GlobalTransactionView(BytesIO(raw[:4] + b"\xfd\x01\x00"), 0, 6).num_vin

    def test_view_skips_are_checked_and_chunked(self):
        tx = self.transaction()
        tx.vout.insert(0, TransactionOutput(5, Script(bytes(4096))))
        raw = tx.serialize()
        stream = TrackingStream(raw)
        view = GlobalTransactionView(stream, 0, len(raw))
        self.assertEqual(view.locktime, 0)
        self.assertEqual(view.vout(1).value, 42)
        self.assertTrue(stream.max_read <= 32)
        stream = TrackingStream(raw[:100])
        with self.assertRaises(PSBTError):
            _ = GlobalTransactionView(stream, 0, len(raw)).locktime
        # Counts with extended encodings retain their actual offsets.
        raw = self.transaction().serialize()
        extended = raw[:4] + b"\xfd\x01\x00" + raw[5:46] + b"\xfd\x01\x00" + raw[47:]
        view = GlobalTransactionView(BytesIO(extended), 0, len(extended))
        self.assertEqual(view.locktime, 0)
        self.assertEqual(view.vout(0).value, 42)

    def test_scope_reads_do_not_rescan_inputs(self):
        tx = self.transaction()
        tx.vin = [TransactionInput(bytes(range(32)), i) for i in range(32)]
        stream = TrackingStream(PSBT(tx).serialize())
        view = PSBTView.view(stream)
        stream.bytes_read = 0
        for i in range(len(tx.vin)):
            self.assertEqual(view.input(i).vin.serialize(), tx.vin[i].serialize())
        self.assertTrue(stream.bytes_read < 2 * len(tx.serialize()))

    def test_view_reuses_checked_script_ranges(self):
        tx = self.transaction()
        tx.vout.insert(0, TransactionOutput(5, Script(bytes(4096))))
        raw = tx.serialize()
        prefix = b"prefix"
        for length in (None, len(raw)):
            stream = TrackingStream(prefix + raw + b"following")
            view = GlobalTransactionView(stream, len(prefix), length)
            self.assertEqual(view.locktime, 0)
            stream.bytes_read = 0
            for _ in range(4):
                stream.seek(len(prefix) + len(raw) + 1)
                self.assertEqual(view.vout(1).value, 42)
            self.assertTrue(stream.bytes_read < 128)
            self.assertTrue(stream.max_read <= 32)
            # Accessed fields still require complete reads after traversal.
            stream.short_at = view.vin0_offset
            error = TransactionError if length is None else PSBTError
            with self.assertRaises(error):
                view.vin(0)

    def test_view_checks_unvisited_ranges_after_external_seek(self):
        raw = self.transaction().serialize()
        for length in (None, len(raw)):
            stream = TrackingStream(raw[:-1])
            view = GlobalTransactionView(stream, 0, length)
            stream.seek(len(raw))
            error = TransactionError if length is None else PSBTError
            with self.assertRaises(error):
                _ = view.locktime

    def test_compressed_memory_and_witness_utxo(self):
        tx = self.transaction()
        tx.vin[0].witness = Witness([b"abc", b""])
        tx.vout = [TransactionOutput(i, Script(b"")) for i in range(512)]
        raw = tx.serialize()
        scope = InputScope(
            vin=TransactionInput(tx.txid(), 511), compress=CompressMode.CLEAR_ALL
        )
        stream = SequentialStream(compact.to_bytes(len(raw)) + raw)
        scope.read_value(stream, b"\x00")
        self.assertEqual(scope._utxo.value, 511)
        self.assertEqual(scope._txhash, tx.hash())
        self.assertTrue(stream.max_read <= 32)

    def test_bounded_view_short_reads_and_output_length(self):
        raw = self.transaction().serialize()
        with self.assertRaises(PSBTError):
            _ = GlobalTransactionView(TrackingStream(raw, 0), 0, len(raw)).version
        # Output script length extends beyond the declared transaction value.
        raw = raw[:55] + b"\x09" + raw[56:]
        for access in (lambda v: v.locktime, lambda v: v.vout(0)):
            stream = TrackingStream(raw + bytes(20))
            with self.assertRaises(PSBTError):
                access(GlobalTransactionView(stream, 0, len(raw)))
            self.assertTrue(stream.tell() <= len(raw))
