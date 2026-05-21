"""
BIP-352 test vectors:
https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json
"""

from binascii import unhexlify
from unittest import TestCase

import pytest
from embit.silent_payments import bip352
from embit.ec import PrivateKey
import os
import json
from embit import hashes
from embit.script import Script, Witness
from embit.transaction import COutPoint
from embit.util.key import ECPubKey
from embit.ec import NUMS_PUBKEY


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
                if len(control_block) >= 33 and control_block[1:33] == NUMS_PUBKEY.xonly():
                    return ECPubKey()
        # Key-path spend: reconstruct even-y compressed SEC from x-only
        if len(spk.data) >= 34:
            pubkey = ECPubKey().set(b"\x02" + spk.data[2:34])
            if pubkey.valid:
                return pubkey

    return ECPubKey()


BASIC_TEST_VECTORS = [
    {
        "spend_priv_key": "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
        "scan_priv_key": "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
        "sp_address": "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
    },
    {
        "spend_priv_key": "0000000000000000000000000000000000000000000000000000000000000001",
        "scan_priv_key": "0000000000000000000000000000000000000000000000000000000000000002",
        "sp_address": "sp1qqtrqglu5g8kh6mfsg4qxa9wq0nv9cauwfwxw70984wkqnw2uwz0w2qnehen8a7wuhwk9tgrzjh8gwzc8q2dlekedec5djk0js9d3d7qhnq6lqj3s",
    },
]


LABEL_TEST_VECTORS = {
    "spend_priv_key": "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
    "scan_priv_key": "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
    "labels": [2, 3, 1001337],
    "addresses": [
        "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjex54dmqmmv6rw353tsuqhs99ydvadxzrsy9nuvk74epvee55drs734pqq",
        "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqsg59z2rppn4qlkx0yz9sdltmjv3j8zgcqadjn4ug98m3t6plujsq9qvu5n",
        "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq7c2zfthc6x3a5yecwc52nxa0kfd20xuz08zyrjpfw4l2j257yq6qgnkdh5",
    ],
}


INVALID_LABEL_TEST_VECTORS = ["not an int", 99999999999999999999999999, -15, 1.0]


class BIP352Test(TestCase):
    def test_generate_silent_payment_address(self):
        """Should generate the expected silent payment address"""
        for test_vector in BASIC_TEST_VECTORS:
            spend_priv_key = PrivateKey(unhexlify(test_vector["spend_priv_key"]))
            scan_priv_key = PrivateKey(unhexlify(test_vector["scan_priv_key"]))
            sp_address = bip352.generate_silent_payment_address(
                scan_priv_key, spend_priv_key.get_public_key()
            )
            assert sp_address == test_vector["sp_address"]

    def test_generate_labeled_silent_payment_address(self):
        """Should generate the expected labeled silent payment addresses"""
        spend_priv_key = PrivateKey(unhexlify(LABEL_TEST_VECTORS["spend_priv_key"]))
        scan_priv_key = PrivateKey(unhexlify(LABEL_TEST_VECTORS["scan_priv_key"]))
        for label, address in zip(
            LABEL_TEST_VECTORS["labels"], LABEL_TEST_VECTORS["addresses"]
        ):
            sp_address = bip352.generate_silent_payment_address(
                scan_priv_key, spend_priv_key.get_public_key(), label
            )
            assert sp_address == address

        with pytest.raises(Exception):
            for label in INVALID_LABEL_TEST_VECTORS:
                bip352.generate_silent_payment_address(
                    scan_priv_key, spend_priv_key.get_public_key(), label
                )

    def test_decode_silent_payment_address(self):
        """Should decode the silent payment address and return the expected keys"""
        for test_vector in BASIC_TEST_VECTORS:
            scan_priv_key = PrivateKey(unhexlify(test_vector["scan_priv_key"]))
            spend_priv_key = PrivateKey(unhexlify(test_vector["spend_priv_key"]))
            B_scan, B_spend = bip352.decode_silent_payment_address(
                test_vector["sp_address"]
            )

            assert B_scan == scan_priv_key.get_public_key()
            assert B_spend == spend_priv_key.get_public_key()

        with pytest.raises(ValueError):
            # Invalid HRP
            bip352.decode_silent_payment_address(
                "st1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"
            )

        with pytest.raises(ValueError):
            # Invalid encoding
            bip352.decode_silent_payment_address(
                "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwvm"
            )

    def test_create_silent_payments_outputs(self):
        """Test silent payment output generation using test vectors"""
        __location__ = os.path.realpath(
            os.path.join(os.getcwd(), os.path.dirname(__file__))
        )
        with open(
            os.path.join(__location__, "data/send_and_receive_test_vectors.json"), "r"
        ) as f:
            SEND_AND_RECEIVE_TEST_VECTORS = json.load(f)

        from io import BytesIO

        for case in SEND_AND_RECEIVE_TEST_VECTORS:
            for sending_test in case["sending"]:
                given = sending_test["given"]
                expected = sending_test["expected"]

                outpoints: list[COutPoint] = []
                input_privkeys: list[tuple] = []

                for txin in given["vin"]:
                    outpoints.append(
                        COutPoint(txid=unhexlify(txin["txid"]), out_idx=txin["vout"])
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
                    input_privkeys.append((unhexlify(txin["private_key"]), is_xonly))

                outputs_map = bip352.create_outputs(
                    input_privkeys=input_privkeys,
                    outpoints=outpoints,
                    recipients=given["recipients"],
                )

                expected_outputs = expected["outputs"]

                actual_outputs = []
                for recipient, outputs in outputs_map.items():
                    actual_outputs.extend(outputs)

                self.assertTrue(
                    any(
                        set(actual_outputs) == set(expected_set)
                        for expected_set in expected_outputs
                    ),
                    f"Actual outputs {set(actual_outputs)} did not match any expected set {expected_outputs}",
                )
