"""
BIP-352 test vectors:
https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json
"""

from binascii import hexlify, unhexlify
from unittest import TestCase

import json
import os

from embit import hashes
from embit.base import EmbitError
from embit.ec import NUMS_PUBKEY, PrivateKey
from embit.networks import NETWORKS
from embit.script import Script, Witness
from embit.silent_payments import sp
from embit.transaction import TransactionInput
from embit.util.key import ECPubKey


def _create_test_outputs(input_privkeys, outpoints, recipients):
    """Test helper: reproduce the old create_outputs behaviour using public API.

    Decodes silent-payment addresses, groups recipients by scan key,
    calls derive_sp_outputs, and formats the result as
    {address: [hex_xonly_pubkey, ...]}.
    """
    if not input_privkeys:
        return {}

    decoded = {}
    for addr in recipients:
        if addr not in decoded:
            decoded[addr] = sp.decode_silent_payment_address(addr)

    scan_spend_groups = {}
    addr_lists = {}
    for addr in recipients:
        B_scan, B_spend = decoded[addr]
        sk_bytes = B_scan.sec()
        if sk_bytes not in scan_spend_groups:
            scan_spend_groups[sk_bytes] = (B_scan, [])
            addr_lists[sk_bytes] = []
        scan_spend_groups[sk_bytes][1].append(B_spend)
        addr_lists[sk_bytes].append(addr)

    derivation = sp.derive_sp_outputs(input_privkeys, outpoints, scan_spend_groups)
    if derivation is None:
        return {}

    _a_sum_bytes, results = derivation

    output = {addr: [] for addr in decoded}
    for sk_bytes, (_ecdh_share, outputs) in results.items():
        for k, addr in enumerate(addr_lists[sk_bytes]):
            output[addr].append(hexlify(outputs[k]).decode())

    return output


def get_input_pubkey(prevout_script, script_sig=None, witness=None) -> ECPubKey:
    """Extract and validate the input pubkey for a prevout, by script type.

    Test helper for BIP-352 send vectors. Returns an ECPubKey with .valid=False
    when no suitable compressed pubkey can be determined.
    """
    spk = (
        prevout_script if isinstance(prevout_script, Script) else Script(prevout_script)
    )

    if isinstance(script_sig, str):
        try:
            ss = bytes.fromhex(script_sig)
        except Exception:
            ss = b""
    elif isinstance(script_sig, bytes):
        ss = script_sig
    else:
        ss = b""

    if isinstance(witness, Witness):
        wstack = witness.items
    elif isinstance(witness, list):
        wstack = witness
    else:
        wstack = []

    script_type = spk.script_type()

    def _compressed(pubkey_bytes):
        pubkey = ECPubKey().set(pubkey_bytes)
        return pubkey if (pubkey.valid and pubkey.is_compressed) else None

    if script_type == "p2pkh":
        spk_hash = spk.data[3:23]
        for i in range(len(ss), 32, -1):
            if i >= 33:
                pubkey_bytes = ss[i - 33 : i]
                if (
                    pubkey_bytes[0] in (0x02, 0x03)
                    and hashes.hash160(pubkey_bytes) == spk_hash
                ):
                    pubkey = _compressed(pubkey_bytes)
                    if pubkey:
                        return pubkey
        return ECPubKey()

    if script_type in ("p2sh", "p2wpkh"):
        if wstack and (script_type == "p2wpkh" or len(ss) > 1):
            pubkey = _compressed(wstack[-1])
            if pubkey:
                return pubkey
        return ECPubKey()

    if script_type == "p2tr":
        if wstack:
            # strip annex if present (last element starting with 0x50)
            if len(wstack) > 1 and wstack[-1][:1] == b"\x50":
                wstack = wstack[:-1]
            # Script-path spend with NUMS internal key: not key-spendable
            if len(wstack) > 1:
                control_block = wstack[-1]
                if (
                    len(control_block) >= 33
                    and control_block[1:33] == NUMS_PUBKEY.xonly()
                ):
                    return ECPubKey()
        # Key-path spend: reconstruct even-y compressed SEC from x-only
        if len(spk.data) >= 34:
            pubkey = ECPubKey().set(b"\x02" + spk.data[2:34])
            if pubkey.valid:
                return pubkey

    return ECPubKey()


BASIC_TEST_VECTORS = [
    {
        "spend_priv_key": "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",  # noqa: E501
        "scan_priv_key": "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",  # noqa: E501
        "sp_address": "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",  # noqa: E501
    },
    {
        "spend_priv_key": "0000000000000000000000000000000000000000000000000000000000000001",  # noqa: E501
        "scan_priv_key": "0000000000000000000000000000000000000000000000000000000000000002",  # noqa: E501
        "sp_address": "sp1qqtrqglu5g8kh6mfsg4qxa9wq0nv9cauwfwxw70984wkqnw2uwz0w2qnehen8a7wuhwk9tgrzjh8gwzc8q2dlekedec5djk0js9d3d7qhnq6lqj3s",  # noqa: E501
    },
]


LABEL_TEST_VECTORS = {
    "spend_priv_key": "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",  # noqa: E501
    "scan_priv_key": "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
    "labels": [2, 3, 1001337],
    "addresses": [
        "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjex54dmqmmv6rw353tsuqhs99ydvadxzrsy9nuvk74epvee55drs734pqq",
        "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqsg59z2rppn4qlkx0yz9sdltmjv3j8zgcqadjn4ug98m3t6plujsq9qvu5n",
        "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq7c2zfthc6x3a5yecwc52nxa0kfd20xuz08zyrjpfw4l2j257yq6qgnkdh5",
    ],
}


INVALID_LABEL_TEST_VECTORS = ["not an int", 99999999999999999999999999, -15, 1.0]


class SilentPaymentsTest(TestCase):
    def test_generate_silent_payment_address(self):
        """Should generate the expected silent payment address"""
        for test_vector in BASIC_TEST_VECTORS:
            spend_priv_key = PrivateKey(unhexlify(test_vector["spend_priv_key"]))
            scan_priv_key = PrivateKey(unhexlify(test_vector["scan_priv_key"]))
            sp_address = sp.generate_silent_payment_address(
                scan_priv_key, spend_priv_key.get_public_key()
            )
            self.assertEqual(sp_address, test_vector["sp_address"])

    def test_generate_labeled_silent_payment_address(self):
        """Should generate the expected labeled silent payment addresses"""
        spend_priv_key = PrivateKey(unhexlify(LABEL_TEST_VECTORS["spend_priv_key"]))
        scan_priv_key = PrivateKey(unhexlify(LABEL_TEST_VECTORS["scan_priv_key"]))
        for label, address in zip(  # noqa: B905
            LABEL_TEST_VECTORS["labels"], LABEL_TEST_VECTORS["addresses"]
        ):
            sp_address = sp.generate_silent_payment_address(
                scan_priv_key, spend_priv_key.get_public_key(), label
            )
            self.assertEqual(sp_address, address)

        for label in INVALID_LABEL_TEST_VECTORS:
            with self.assertRaises((TypeError, sp.SPValidationError)):
                sp.generate_silent_payment_address(
                    scan_priv_key, spend_priv_key.get_public_key(), label
                )

    def test_decode_silent_payment_address(self):
        """Should decode the silent payment address and return the expected keys"""
        for test_vector in BASIC_TEST_VECTORS:
            scan_priv_key = PrivateKey(unhexlify(test_vector["scan_priv_key"]))
            spend_priv_key = PrivateKey(unhexlify(test_vector["spend_priv_key"]))
            B_scan, B_spend = sp.decode_silent_payment_address(
                test_vector["sp_address"]
            )

            self.assertEqual(B_scan, scan_priv_key.get_public_key())
            self.assertEqual(B_spend, spend_priv_key.get_public_key())

        with self.assertRaises(sp.SPValidationError):
            # Invalid HRP
            sp.decode_silent_payment_address(
                "st1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"
            )

        with self.assertRaises(sp.SPValidationError):
            # Invalid encoding
            sp.decode_silent_payment_address(
                "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwvm"
            )

    def test_create_silent_payments_outputs(self):
        """Test silent payment output generation using test vectors"""
        __location__ = os.path.realpath(
            os.path.join(os.getcwd(), os.path.dirname(__file__))
        )
        with open(
            os.path.join(__location__, "data/bip352_send_test_vectors.json"), "r"
        ) as f:
            SEND_AND_RECEIVE_TEST_VECTORS = json.load(f)

        from io import BytesIO

        for case in SEND_AND_RECEIVE_TEST_VECTORS:
            for sending_test in case["sending"]:
                given = sending_test["given"]
                expected = sending_test["expected"]

                outpoints = []
                input_privkeys = []

                for txin in given["vin"]:
                    outpoints.append(
                        TransactionInput(
                            txid=unhexlify(txin["txid"]), vout=txin["vout"]
                        )
                    )

                    spk_hex = txin["prevout"]["scriptPubKey"]["hex"]
                    spk = Script(unhexlify(spk_hex))

                    wit_hex = txin.get("txinwitness", "") or ""
                    witness = None
                    if wit_hex:
                        try:
                            witness = Witness.read_from(BytesIO(bytes.fromhex(wit_hex)))
                        except Exception:
                            witness = None

                    pub = get_input_pubkey(spk, txin.get("scriptSig", ""), witness)
                    if not getattr(pub, "valid", False):
                        continue

                    is_xonly = spk.script_type() == "p2tr"
                    priv = unhexlify(txin["private_key"])
                    if is_xonly:
                        priv = PrivateKey(priv).even_y().secret
                    input_privkeys.append(priv)

                outputs_map = _create_test_outputs(
                    input_privkeys=input_privkeys,
                    outpoints=outpoints,
                    recipients=given["recipients"],
                )

                expected_outputs = expected["outputs"]

                actual_outputs = []
                for _recipient, outputs in outputs_map.items():
                    actual_outputs.extend(outputs)

                self.assertTrue(
                    any(
                        set(actual_outputs) == set(expected_set)
                        for expected_set in expected_outputs
                    ),
                    "Actual outputs {} did not match any expected set {}".format(
                        set(actual_outputs), expected_outputs
                    ),
                )

    def test_create_outputs_rejects_too_many_outputs_per_scan_key(self):
        """Should fail when one scan-key group exceeds K_MAX recipients"""
        vector = BASIC_TEST_VECTORS[0]
        input_privkeys = [unhexlify(vector["spend_priv_key"])]
        outpoints = [TransactionInput(txid=bytes(32), vout=0)]
        recipients = [vector["sp_address"]] * (sp.K_MAX + 1)

        with self.assertRaises(sp.SPValidationError):
            _create_test_outputs(input_privkeys, outpoints, recipients)

    def test_derive_outputs_rejects_too_many_outputs_per_scan_key(self):
        """Should fail when the per-scan-key recipient list exceeds K_MAX"""
        vector = BASIC_TEST_VECTORS[0]
        _B_scan, B_spend = sp.decode_silent_payment_address(vector["sp_address"])
        spend_keys = [B_spend] * (sp.K_MAX + 1)

        with self.assertRaises(sp.SPValidationError):
            sp.derive_recipient_outputs(b"\x02" + bytes(32), spend_keys)

    def test_create_outputs_assigns_k_by_vout_order_when_interleaved(self):
        """Addresses sharing a scan key get k by recipients-list (vout) order,
        not grouped per address. Regression test matching the BIP-375
        validator's derivation order for interleaved recipients."""
        # Two addresses with a common scan key but distinct spend keys.
        scan_priv = PrivateKey(b"\x11" * 32)
        addr_x = sp.generate_silent_payment_address(
            scan_priv, PrivateKey(b"\x22" * 32).get_public_key()
        )
        addr_y = sp.generate_silent_payment_address(
            scan_priv, PrivateKey(b"\x33" * 32).get_public_key()
        )

        input_privkeys = [b"\x44" * 32]
        outpoints = [TransactionInput(txid=bytes(32), vout=0)]

        # The shared secret depends only on (inputs, outpoints, scan key), so
        # single-address runs yield the per-k outputs to compare against.
        out_x = _create_test_outputs(input_privkeys, outpoints, [addr_x] * 3)[addr_x]
        out_y = _create_test_outputs(input_privkeys, outpoints, [addr_y] * 3)[addr_y]

        # Interleaved vout order [X, Y, X] -> k = 0, 1, 2.
        result = _create_test_outputs(
            input_privkeys, outpoints, [addr_x, addr_y, addr_x]
        )

        self.assertEqual(result[addr_x][0], out_x[0])  # first X  -> k=0
        self.assertEqual(result[addr_y][0], out_y[1])  # Y        -> k=1
        self.assertEqual(result[addr_x][1], out_x[2])  # second X -> k=2
        # The old count-collapsing code assigned the second X to k=1.
        self.assertNotEqual(result[addr_x][1], out_x[1])

    def test_encode_matches_generate_unlabeled(self):
        """encode_silent_payment_address is the same encoding
        generate_silent_payment_address falls back to when there's no label."""
        scan_priv = PrivateKey(b"\x11" * 32)
        spend_pub = PrivateKey(b"\x22" * 32).get_public_key()

        expected = sp.generate_silent_payment_address(scan_priv, spend_pub)
        actual = sp.encode_silent_payment_address(scan_priv.get_public_key(), spend_pub)
        self.assertEqual(actual, expected)

    def test_apply_label_matches_generate_labeled(self):
        """apply_label + encode_silent_payment_address reproduces what
        generate_silent_payment_address does internally for a label."""
        scan_priv = PrivateKey(b"\x11" * 32)
        spend_pub = PrivateKey(b"\x22" * 32).get_public_key()
        m = 7

        expected = sp.generate_silent_payment_address(scan_priv, spend_pub, label=m)
        labeled_spend = sp.apply_label(spend_pub, scan_priv, m)
        actual = sp.encode_silent_payment_address(
            scan_priv.get_public_key(), labeled_spend
        )
        self.assertEqual(actual, expected)

    def test_apply_label_allows_zero_for_change(self):
        """m = 0 is reserved for change and generate_silent_payment_address
        forbids it, but apply_label itself must allow it (used by change
        detection, not address generation)."""
        scan_priv = PrivateKey(b"\x11" * 32)
        spend_pub = PrivateKey(b"\x22" * 32).get_public_key()

        with self.assertRaises(sp.SPValidationError):
            sp.generate_silent_payment_address(scan_priv, spend_pub, label=0)

        # Should not raise.
        sp.apply_label(spend_pub, scan_priv, 0)
