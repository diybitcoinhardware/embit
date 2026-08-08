from io import BytesIO
from unittest import TestCase

from embit import compact
from embit.psbt import InputScope, OutputScope, PSBT, PSBTError
from embit.psbtview import PSBTView
from embit.script import Script
from embit.transaction import Transaction, TransactionInput, TransactionOutput


def key_value(key, value):
    return (
        compact.to_bytes(len(key))
        + key
        + compact.to_bytes(len(value))
        + value
    )


def psbt_v0():
    tx = Transaction(
        vin=[TransactionInput(bytes(32), 0)],
        vout=[TransactionOutput(1000, Script(b"\x51"))],
    )
    return PSBT(tx).serialize()


class PSBTVersionTest(TestCase):
    def test_v0_excludes_v2_input_fields(self):
        raw = psbt_v0()
        fields = [
            (b"\x0e", bytes(32)),
            (b"\x0f", bytes(4)),
            (b"\x10", bytes(4)),
            (b"\x11", bytes(4)),
            (b"\x12", bytes(4)),
        ]
        for key, value in fields:
            invalid = raw[:-2] + key_value(key, value) + raw[-2:]
            with self.assertRaises(PSBTError):
                PSBT.parse(invalid)
            view = PSBTView.view(BytesIO(invalid))
            with self.assertRaises(PSBTError):
                view.input(0)

    def test_v0_excludes_v2_output_fields(self):
        raw = psbt_v0()
        fields = [
            (b"\x03", (1000).to_bytes(8, "little")),
            (b"\x04", b"\x51"),
        ]
        for key, value in fields:
            invalid = raw[:-1] + key_value(key, value) + raw[-1:]
            with self.assertRaises(PSBTError):
                PSBT.parse(invalid)
            view = PSBTView.view(BytesIO(invalid))
            with self.assertRaises(PSBTError):
                view.output(0)

    def test_v0_excludes_v2_fields_with_key_data(self):
        raw = psbt_v0()
        fields = [
            (b"\x0e\x00", bytes(32), -2, "input"),
            (b"\x03\x00", (1000).to_bytes(8, "little"), -1, "output"),
        ]
        for key, value, offset, scope in fields:
            invalid = raw[:offset] + key_value(key, value) + raw[offset:]
            with self.assertRaises(PSBTError):
                PSBT.parse(invalid)
            view = PSBTView.view(BytesIO(invalid))
            with self.assertRaises(PSBTError):
                getattr(view, scope)(0)

    def test_global_version_2_rejected_with_unsigned_tx_in_any_order(self):
        tx = Transaction(
            vin=[TransactionInput(bytes(32), 0)],
            vout=[TransactionOutput(1000, Script(b"\x51"))],
        )
        tx_kv = key_value(b"\x00", tx.serialize())
        version_kv = key_value(b"\xfb", (2).to_bytes(4, "little"))
        # the global map is unordered, so both orderings must be rejected
        for globals_ in (version_kv + tx_kv, tx_kv + version_kv):
            raw = PSBT.MAGIC + globals_ + b"\x00" + b"\x00" + b"\x00"
            with self.assertRaises(PSBTError):
                PSBT.parse(raw)
            with self.assertRaises(PSBTError):
                PSBTView.view(BytesIO(raw))

    def test_v0_rejects_v2_output_scope(self):
        raw = psbt_v0()
        output_data = key_value(
            b"\x03", (1000).to_bytes(8, "little")
        ) + key_value(b"\x04", b"\x52")
        invalid = raw[:-1] + output_data + raw[-1:]

        with self.assertRaises(PSBTError):
            PSBT.parse(invalid)
        view = PSBTView.view(BytesIO(invalid))
        with self.assertRaises(PSBTError):
            view.output(0)

    def test_v0_rejects_v2_prevout_metadata(self):
        raw = psbt_v0()
        previous_tx = Transaction(
            vin=[TransactionInput(bytes([1]) * 32, 0)],
            vout=[TransactionOutput(2000, Script(b"\x51"))],
        )
        input_data = key_value(
            b"\x00", previous_tx.serialize()
        ) + key_value(b"\x0e", bytes(reversed(previous_tx.txid())))
        invalid = raw[:-2] + input_data + raw[-2:]

        with self.assertRaises(PSBTError):
            PSBT.parse(invalid)
        view = PSBTView.view(BytesIO(invalid))
        with self.assertRaises(PSBTError):
            view.input(0)

    def test_v2_scope_fields_remain_compatible(self):
        input_data = (
            key_value(b"\x0e", bytes(range(32)))
            + key_value(b"\x0f", (3).to_bytes(4, "little"))
            + key_value(b"\x10", (4).to_bytes(4, "little"))
            + b"\x00"
        )
        inp = InputScope.read_from(BytesIO(input_data), version=2)
        self.assertEqual(inp.txid, bytes(reversed(range(32))))
        self.assertEqual(inp.vout, 3)
        self.assertEqual(inp.sequence, 4)

        output_data = (
            key_value(b"\x03", (1000).to_bytes(8, "little"))
            + key_value(b"\x04", b"\x51")
            + b"\x00"
        )
        out = OutputScope.read_from(BytesIO(output_data), version=2)
        self.assertEqual(out.value, 1000)
        self.assertEqual(out.script_pubkey, Script(b"\x51"))

    def test_v2_fields_reject_key_data(self):
        fields = [
            (InputScope, b"\x0e\x00", bytes(32)),
            (OutputScope, b"\x03\x00", (1000).to_bytes(8, "little")),
        ]
        for scope_cls, key, value in fields:
            data = key_value(key, value) + b"\x00"
            with self.assertRaises(PSBTError):
                scope_cls.read_from(BytesIO(data), version=2)

    def test_unknown_fields_with_key_data_remain_compatible(self):
        key = b"\xf0\x00"
        value = b"unknown"
        data = key_value(key, value) + b"\x00"

        inp = InputScope.read_from(BytesIO(data), version=0)
        self.assertEqual(inp.unknown[key], value)

        out = OutputScope.read_from(BytesIO(data), version=2)
        self.assertEqual(out.unknown[key], value)
