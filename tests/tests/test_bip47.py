from unittest import TestCase
from unittest.mock import patch

from embit import base58, bip32, bip39, bip47, ec, compact, finalizer
from embit.networks import NETWORKS
from embit.psbt import PSBT, OutputScope
from embit.script import OPCODES, Script, p2wpkh
from embit.transaction import Transaction, TransactionInput, TransactionOutput, Witness
from binascii import unhexlify


# Test vectors from: https://gist.github.com/SamouraiDev/6aad669604c5930864bd
ALICE_MNEMONIC = "response seminar brave tip suit recall often sound stick owner lottery motion"
ALICE_PAYMENT_CODE = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA"
ALICE_PAYMENT_CODE_REGTEST = "PM8TJcUtZbTqYoGWcNAnaYDkAzA1cLq6gQV4aPJ3N5jydgmTHUr5UFK74CU58mdL6V8pVo3JJ8JsJFJzriZSGMj27ujJ3jxwFUQwi49ox3Cfai4SG5rk"
ALICE_NOTIFICATION_ADDR = "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW"
ALICE_NOTIFICATION_ADDR_REGTEST = "mod1FsW4dsVRod4ZVRR3D3ovY97SxSjJwk"
ALICE_NOTIFICATION_INPUT_PRIVATE_KEY = "Kx983SRhAZpAhj7Aac1wUXMJ6XZeyJKqCxJJ49dxEbYCT4a1ozRD"
ALICE_NOTIFICATION_INPUT_OUTPOINT = "86f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c01000000"
ALICE_NOTIFICATION_BLINDED_PAYLOAD = "010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b00000000000000000000000000"


# Mainnet p2pkh from BIP-47 test vectors, remaining addrs generated from https://bitcoiner.guide/seed
ALICE_PAYS_BOB_ADDRS = {
    "main": {
        "p2wpkh": [
            "bc1qyyytpxv60e6hwh5jqkj2dcenckdsw6ekn2htfq",
            "bc1qzn8a8drxv6ln7rztjsw660gzf3hnrfwupzmsfh",
            "bc1q5v84r4dq2vkdku8h7ewfkj6c00eh20gmf0amr5",
            "bc1q06ld55yrxrqdfym235h0jvdddvwc72ktsamh7c",
            "bc1qe8uxekd8s59szxgnnfd2nxrn3ncnkmxlku83l9",
            "bc1qemm4xmwr0fxwysry5mur0r5q5kakkw79fpezx0",
            "bc1q3fl6rfkg4f600tlfrtkn6jv6kndg9tfu3hr009",
            "bc1q89zc0ptgrcgsrzkfe4fjrlwcwfvny908976vxh",
            "bc1qfteug4efvdlhyek9p9mrgwk0kqsq74y8jm5qw7",
            "bc1q4ugsxkh69aknjvskm8k2susv9c6dq0pp3476y0"
        ],
        "p2pkh": [
            "141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK",
            "12u3Uued2fuko2nY4SoSFGCoGLCBUGPkk6",
            "1FsBVhT5dQutGwaPePTYMe5qvYqqjxyftc",
            "1CZAmrbKL6fJ7wUxb99aETwXhcGeG3CpeA",
            "1KQvRShk6NqPfpr4Ehd53XUhpemBXtJPTL",
            "1KsLV2F47JAe6f8RtwzfqhjVa8mZEnTM7t",
            "1DdK9TknVwvBrJe7urqFmaxEtGF2TMWxzD",
            "16DpovNuhQJH7JUSZQFLBQgQYS4QB9Wy8e",
            "17qK2RPGZMDcci2BLQ6Ry2PDGJErrNojT5",
            "1GxfdfP286uE24qLZ9YRP3EWk2urqXgC4s",
        ],
        "p2sh-p2wpkh": [
            "3QnEFKkpXFYSipn4uqcMNAKWhZq6PD4Gmz",
            "38mr84Lrer3j1pTEZpTJ1pQTQJweMcc4YC",
            "37Q2nDn2MGPLR2eCSRRnx3EZUv1bgNJpH3",
            "38KnaMF7yiGnuUxDuM5AYoU7biYaGEfaRg",
            "38A9WgnPYfNwDbovo12sSGF4E8Kq67qHvc",
            "3A41gu3kgtqPpiWQwp5fY5VVS5WNgT11nN",
            "33prMnukiGDj4vdwD7r3WV7fDuWxWAFEh5",
            "38qRxEnED8hMVqQMywJydEmK595gBXi6yQ",
            "3QH8LrqkkTnLNcaq5dsBzcj5LCoo5U8pEz",
            "3ALkcRwUk1QhkZhcG7t9ooAAu7o12MGQr7",
        ],
    },
    "test": {
        "p2wpkh": [
            "tb1qvlcks6jystdc984whpcqwm0ftuwvk888w3phmk",
            "tb1qrzn3xca8ll4v6j65956ywslwzn7mu8d2t00xqa",
            "tb1qwynwpawd5t3twd7yepk8v8wz4cewtel5z88tn5",
            "tb1q3a6ltk6pycyy4ds5lt67whrglude5l85l0ru43",
            "tb1qx630tnvjdx98r6cukv905ltn6ndtyr9zmvdp4l",
            "tb1quqe2w3jz334gyadtns0gjzn535dsy8jlrkmdgt",
            "tb1q4353mvaglaflcxk65u3t579pn4lgle5vldvpty",
            "tb1qj5j0xrujhh0fns4q353q8uf970d6dp5xnacq6a",
            "tb1qkqrwshzah97q5dmfz7pr7vfk4saulqsyvnyrth",
            "tb1qwvsls5tydc7pw0f0r93ypexcyfundyve5z5t25",
        ],
        "p2pkh": [
            "mpzZ68EWiTQ3kb8dLoJ8YYd5yH8YaTHYvR",
            "mhmJfHR5YJosP3CWm9fYrv1Sm5CJrTZ9Yd",
            "mqqFE5EZGwSxAdfGR9NM4BskZbdyjN1h1g",
            "mtbWEWuYrhaxZPposbVPBtgsZoEn1ZiczJ",
            "mkVr15pHUVEnwi9L9cc61K8A5zcMbv2cox",
            "n1xQLV627ei3exa7jXedAFEw2DcdgQSDoS",
            "mwEaSdxyqPvTpvytzWkSqcPQBiX8Qmh9hB",
            "mu7ZEvtjwqu8kwqkjFqZqi1KEVS3nvfVEu",
            "mwZhVmYNhZLfsM7YnLCCABnatS27CtyYyD",
            "mr1ihPdNQYqyAxWcV6MEZgwgzW1bmfUyXH",
        ],
        "p2sh-p2wpkh": [
            "2MxeHXEAqnX45Lc5pW5WJepo1PbaBiGVa4i",
            "2N65jANRymkKniZXtdmud2ycLdbC9yPheU3",
            "2NE4CDQbkbzJ6HAuYgStwHAhK2WhPQu4yqq",
            "2N8f9kvkGoJ1oZdn63pUpewgzmwX9S1sY7K",
            "2NB69mKr5v8b4AsgZZrTU5yMEu56yVCRgQQ",
            "2NCmmAswkz6nL7Td7KUx9paMLNC1dHyDHhs",
            "2Mwp4ufTEoqSgWuGvhp528EwQHT7StY5pDc",
            "2NGM11Heusc71BpztycAgmG1yBgXy3D5WKe",
            "2MwBYsrDuv4B64otzC5EampPJRmQyZaJQKo",
            "2N12k1GuMrywSFGe1wBDk1v2j8eiw7SP77P",
        ],
    },
    "regtest": {
        "p2wpkh": [
            "bcrt1qvlcks6jystdc984whpcqwm0ftuwvk888vcc6vl",
            "bcrt1qrzn3xca8ll4v6j65956ywslwzn7mu8d2fxkth5",
            "bcrt1qwynwpawd5t3twd7yepk8v8wz4cewtel5qw7xya",
            "bcrt1q3a6ltk6pycyy4ds5lt67whrglude5l85ax63zc",
            "bcrt1qx630tnvjdx98r6cukv905ltn6ndtyr9ze95vzk",
            "bcrt1quqe2w3jz334gyadtns0gjzn535dsy8jlplzqlz",
            "bcrt1q4353mvaglaflcxk65u3t579pn4lgle5vay4vud",
            "bcrt1qj5j0xrujhh0fns4q353q8uf970d6dp5x35pdd5",
            "bcrt1qkqrwshzah97q5dmfz7pr7vfk4saulqsyw6awu7",
            "bcrt1qwvsls5tydc7pw0f0r93ypexcyfundyvektdxaa",
        ],
    },
}

BOB_MNEMONIC = "reward upper indicate eight swift arch injury crystal super wrestle already dentist"
BOB_PAYMENT_CODE = "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97"
BOB_PAYMENT_CODE_REGTEST = "PM8TJMJnBXShCFdcGRaGiCrhcCXczikNSyXJeAES6ciFMBv9jNY3ZwEc8fSV8DLmNRqnP9RPP1NPDxUf6vBoUnohPt5bwFFpTvosRw7gV2W4Tr34MULo"
BOB_NOTIFICATION_ADDR = "1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV"
BOB_NOTIFICATION_ADDR_REGTEST = "mrVYeCNDyrzYwUuZNMWTFL76wdQ3mfXYHL"

ALICE_NOTIFICATION_TX_FOR_BOB = "010000000186f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c010000006b483045022100ac8c6dbc482c79e86c18928a8b364923c774bfdbd852059f6b3778f2319b59a7022029d7cc5724e2f41ab1fcfc0ba5a0d4f57ca76f72f19530ba97c860c70a6bf0a801210272d83d8a1fa323feab1c085157a0791b46eba34afb8bfbfaeb3a3fcc3f2c9ad8ffffffff0210270000000000001976a9148066a8e7ee82e5c5b9b7dc1765038340dc5420a988ac1027000000000000536a4c50010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b0000000000000000000000000000000000"


class Bip47Test(TestCase):

    def test_get_payment_code(self):
        """Alice & Bob's payment codes should match the test vectors in BIP-47"""
        # Generate Alice's payment code
        seed_bytes = bip39.mnemonic_to_seed(ALICE_MNEMONIC)
        root = bip32.HDKey.from_seed(seed_bytes)
        payment_code = bip47.get_payment_code(root)
        self.assertEqual(payment_code, ALICE_PAYMENT_CODE)

        # Generate Bob's payment code
        seed_bytes = bip39.mnemonic_to_seed(BOB_MNEMONIC)
        root = bip32.HDKey.from_seed(seed_bytes)
        payment_code = bip47.get_payment_code(root)
        self.assertEqual(payment_code, BOB_PAYMENT_CODE)
    

    def test_get_payment_code_regtest(self):
        """Regtest payment codes are different from mainnet and should be properly generated"""
        seed_bytes = bip39.mnemonic_to_seed(ALICE_MNEMONIC)
        root = bip32.HDKey.from_seed(seed_bytes)

        # coin=1 for test/regtest, per BIP-44
        payment_code = bip47.get_payment_code(root, coin=1)
        self.assertEqual(payment_code, ALICE_PAYMENT_CODE_REGTEST)

        seed_bytes = bip39.mnemonic_to_seed(BOB_MNEMONIC)
        root = bip32.HDKey.from_seed(seed_bytes)
        payment_code = bip47.get_payment_code(root, coin=1)
        self.assertEqual(payment_code, BOB_PAYMENT_CODE_REGTEST)


    def test_get_notification_address(self):
        """Alice & Bob's derived notification addresses should match the test vectors in BIP-47"""
        self.assertEqual(bip47.get_notification_address(ALICE_PAYMENT_CODE), ALICE_NOTIFICATION_ADDR)
        self.assertEqual(bip47.get_notification_address(BOB_PAYMENT_CODE), BOB_NOTIFICATION_ADDR)
    

    def test_get_notification_address_regtest(self):
        """Regtest notification addresses are different from mainnet and should be properly generated"""
        self.assertEqual(bip47.get_notification_address(ALICE_PAYMENT_CODE_REGTEST, network=NETWORKS["regtest"]), ALICE_NOTIFICATION_ADDR_REGTEST)
        self.assertEqual(bip47.get_notification_address(BOB_PAYMENT_CODE_REGTEST, network=NETWORKS["regtest"]), BOB_NOTIFICATION_ADDR_REGTEST)


    def test_get_derived_payment_code_node_rejects_wrong_length(self):
        """A Base58Check string with a valid checksum but wrong decoded length
            (e.g., a P2PKH address — 21 bytes after checksum) must be rejected
            rather than silently mis-derived."""
        # ALICE_NOTIFICATION_ADDR is a P2PKH address: valid Base58Check, but
        # only 21 decoded bytes — nowhere near the 81 a payment code requires.
        with self.assertRaises(bip47.BIP47Exception):
            bip47.get_derived_payment_code_node(ALICE_NOTIFICATION_ADDR, derivation_index=0)


    def test_get_derived_payment_code_node_rejects_wrong_prefix(self):
        """A correctly-sized payment code with a leading byte other than 0x47
            must be rejected (it's the BIP-47 protocol marker)."""
        raw = bytearray(base58.decode_check(ALICE_PAYMENT_CODE))
        raw[0] = 0x48  # any value other than 0x47
        bad_payment_code = base58.encode_check(bytes(raw))

        with self.assertRaises(bip47.BIP47Exception):
            bip47.get_derived_payment_code_node(bad_payment_code, derivation_index=0)


    def test_get_derived_payment_code_node_rejects_unsupported_version(self):
        """A correctly-prefixed payment code with a version byte other than 1
            must be rejected (only v1 is currently supported)."""
        raw = bytearray(base58.decode_check(ALICE_PAYMENT_CODE))
        raw[1] = 0x02  # bump version
        bad_payment_code = base58.encode_check(bytes(raw))

        with self.assertRaises(bip47.BIP47Exception):
            bip47.get_derived_payment_code_node(bad_payment_code, derivation_index=0)


    # _validate_payment_code covers shared format checks for both the
    # caller-facing decode path and the OP_RETURN unblind path. Test it directly
    # to keep each validation branch isolated from end-to-end setup.
    def _canonical_raw(self):
        # 81-byte canonical payment code (0x47 prefix + 80-byte body).
        return base58.decode_check(ALICE_PAYMENT_CODE)


    def test_validate_payment_code_accepts_canonical(self):
        # Returns None implicitly on success; test that no exception is raised.
        bip47._validate_payment_code(self._canonical_raw())


    def test_validate_payment_code_rejects_wrong_length(self):
        with self.assertRaises(bip47.BIP47Exception):
            bip47._validate_payment_code(b"\x47\x01\x00" + b"\x00" * 50)


    def test_validate_payment_code_rejects_wrong_prefix(self):
        raw = bytearray(self._canonical_raw())
        raw[0] = 0x48
        with self.assertRaises(bip47.BIP47Exception):
            bip47._validate_payment_code(bytes(raw))


    def test_validate_payment_code_rejects_unsupported_version(self):
        raw = bytearray(self._canonical_raw())
        raw[1] = 0x02
        with self.assertRaises(bip47.BIP47Exception):
            bip47._validate_payment_code(bytes(raw))


    def test_validate_payment_code_rejects_invalid_pubkey(self):
        raw = bytearray(self._canonical_raw())
        raw[3] = 0x00  # invalid sign byte for compressed pubkey
        with self.assertRaises(bip47.BIP47Exception):
            bip47._validate_payment_code(bytes(raw))


    def test_validate_payment_code_rejects_nonzero_reserved(self):
        raw = bytearray(self._canonical_raw())
        raw[80] = 0xFF
        with self.assertRaises(bip47.BIP47Exception):
            bip47._validate_payment_code(bytes(raw))


    def test_get_payment_address(self):
        """ Alice's payment addresses to Bob's payment code should match the test vector
            addresses in BIP-47 and additional ones generated by Seed Tool. """
        seed_bytes = bip39.mnemonic_to_seed(ALICE_MNEMONIC)
        payer_root = bip32.HDKey.from_seed(seed_bytes)

        # Test against all the networks and script types for Alice pays Bob
        for network, addrs_dict in ALICE_PAYS_BOB_ADDRS.items():
            if network == "main":
                coin = 0
                recipient_payment_code = BOB_PAYMENT_CODE
            else:
                coin = 1   # for test/regtest, per BIP-44
                recipient_payment_code = BOB_PAYMENT_CODE_REGTEST
            for script_type, addrs in addrs_dict.items():
                for i, addr in enumerate(addrs):
                    payment_addr = bip47.get_payment_address(
                        payer_root=payer_root,
                        recipient_payment_code=recipient_payment_code,
                        coin=coin,
                        index=i,
                        network=NETWORKS[network],
                        script_type=script_type,
                    )
                    self.assertEqual(addr, payment_addr)

        # Unsupported script_type should raise
        with self.assertRaises(bip47.BIP47Exception):
            bip47.get_payment_address(
                payer_root=payer_root,
                recipient_payment_code=BOB_PAYMENT_CODE,
                index=0,
                script_type="p2tr",
            )


    def test_get_receive_address(self):
        """ Bob (the recipient) should be able to use Alice's payment code to generate the
            same addresses that Alice (the payer) generated. """
        # Test against all the networks and script types for A pays B
        seed_bytes = bip39.mnemonic_to_seed(BOB_MNEMONIC)
        recipient_root = bip32.HDKey.from_seed(seed_bytes)

        for network, addr_dict in ALICE_PAYS_BOB_ADDRS.items():
            if network == "main":
                coin = 0
                payer_payment_code = ALICE_PAYMENT_CODE
            else:
                coin = 1   # for test/regtest, per BIP-44
                payer_payment_code = ALICE_PAYMENT_CODE_REGTEST
            for script_type, addrs in addr_dict.items():
                for i, addr in enumerate(addrs):
                    payment_addr, spending_key = bip47.get_receive_address(
                        recipient_root=recipient_root,
                        payer_payment_code=payer_payment_code,
                        coin=coin,
                        index=i,
                        network=NETWORKS[network],
                        script_type=script_type,
                    )
                    self.assertEqual(addr, payment_addr)

        # Unsupported script_type should raise
        with self.assertRaises(bip47.BIP47Exception):
            bip47.get_receive_address(
                recipient_root=recipient_root,
                payer_payment_code=ALICE_PAYMENT_CODE,
                index=0,
                script_type="p2tr",
            )


    def test_payment_address_raises_on_invalid_shared_secret(self):
        """Per BIP-47, if the derived shared secret SHA256(Sx) isn't a valid
            secp256k1 scalar, the function must raise BIP47Exception so the
            caller can retry with the next index.

            We can't trigger this with a hardcoded "bad" index: failure region
            is ~2^-128 of the SHA256 output space — cosmologically infeasible
            to brute-force. Instead, mock ec_seckey_verify with a side_effect
            that lets the 4 derivation-time calls (m/47'/coin'/account'/0)
            succeed, then forces False on the 5th call — the BIP-47 check."""
        seed_bytes = bip39.mnemonic_to_seed(ALICE_MNEMONIC)
        payer_root = bip32.HDKey.from_seed(seed_bytes)

        with patch.object(bip47.secp256k1, "ec_seckey_verify",
                          side_effect=[True] * 4 + [False]):
            with self.assertRaises(bip47.BIP47Exception):
                bip47.get_payment_address(
                    payer_root=payer_root,
                    recipient_payment_code=BOB_PAYMENT_CODE,
                    index=0,
                )


    def test_receive_address_raises_on_invalid_shared_secret(self):
        """Recipient-side mirror of the above; see that test for why we mock
            instead of using a real triggering index."""
        seed_bytes = bip39.mnemonic_to_seed(BOB_MNEMONIC)
        recipient_root = bip32.HDKey.from_seed(seed_bytes)

        with patch.object(bip47.secp256k1, "ec_seckey_verify",
                          side_effect=[True] * 4 + [False]):
            with self.assertRaises(bip47.BIP47Exception):
                bip47.get_receive_address(
                    recipient_root=recipient_root,
                    payer_payment_code=ALICE_PAYMENT_CODE,
                    index=0,
                )


    def test_get_blinded_payment_code(self):
        """Alice should be able to blind her payment code for Bob to unblind"""
        input_utxo_private_key = ec.PrivateKey.from_string(ALICE_NOTIFICATION_INPUT_PRIVATE_KEY)
        blinded_payload = bip47.get_blinded_payment_code(
            payer_payment_code=ALICE_PAYMENT_CODE,
            input_utxo_private_key=input_utxo_private_key,
            input_utxo_outpoint=ALICE_NOTIFICATION_INPUT_OUTPOINT,
            recipient_payment_code=BOB_PAYMENT_CODE
        )

        self.assertEqual(blinded_payload, ALICE_NOTIFICATION_BLINDED_PAYLOAD)

        # Wrong-length outpoint (e.g. a full vin serialization) must raise BIP47Exception
        with self.assertRaises(bip47.BIP47Exception):
            bip47.get_blinded_payment_code(
                payer_payment_code=ALICE_PAYMENT_CODE,
                input_utxo_private_key=input_utxo_private_key,
                input_utxo_outpoint=ALICE_NOTIFICATION_INPUT_OUTPOINT + "deadbeef",
                recipient_payment_code=BOB_PAYMENT_CODE,
            )


    def test_get_blinded_payment_code_rejects_malformed_payer_payment_code(self):
        """A Base58Check string with a valid checksum but non-canonical payload
            (wrong length, wrong prefix, etc.) must be rejected before blinding.
            Otherwise blinding_function silently produces a malformed payload
            because its slices truncate via zip() to the shorter input."""
        input_utxo_private_key = ec.PrivateKey.from_string(ALICE_NOTIFICATION_INPUT_PRIVATE_KEY)

        # P2PKH address: valid Base58Check, but only 21 decoded bytes.
        with self.assertRaises(bip47.BIP47Exception):
            bip47.get_blinded_payment_code(
                payer_payment_code=ALICE_NOTIFICATION_ADDR,
                input_utxo_private_key=input_utxo_private_key,
                input_utxo_outpoint=ALICE_NOTIFICATION_INPUT_OUTPOINT,
                recipient_payment_code=BOB_PAYMENT_CODE,
            )

        # Right length, wrong 0x47 prefix.
        raw = bytearray(base58.decode_check(ALICE_PAYMENT_CODE))
        raw[0] = 0x48
        bad_payment_code = base58.encode_check(bytes(raw))
        with self.assertRaises(bip47.BIP47Exception):
            bip47.get_blinded_payment_code(
                payer_payment_code=bad_payment_code,
                input_utxo_private_key=input_utxo_private_key,
                input_utxo_outpoint=ALICE_NOTIFICATION_INPUT_OUTPOINT,
                recipient_payment_code=BOB_PAYMENT_CODE,
            )


    def test_get_payment_code_from_notification_tx(self):
        """Bob should be able to decode Alice's payment code from her notification tx"""
        tx = Transaction.from_string(ALICE_NOTIFICATION_TX_FOR_BOB)
        seed_bytes = bip39.mnemonic_to_seed(BOB_MNEMONIC)
        recipient_root = bip32.HDKey.from_seed(seed_bytes)

        payer_payment_code = bip47.get_payment_code_from_notification_tx(tx, recipient_root)
        self.assertEqual(payer_payment_code, ALICE_PAYMENT_CODE)

        # Any other root should fail
        seed_bytes = bip39.mnemonic_to_seed("abandon " * 11 + "about")
        other_root = bip32.HDKey.from_seed(seed_bytes)
        self.assertTrue(bip47.get_payment_code_from_notification_tx(tx, other_root) is None)


    def test_get_payment_code_from_notification_tx_rejects_too_few_outputs(self):
        """A notification tx must have at least 2 outputs (notification address +
            OP_RETURN); a tx with fewer should be rejected."""
        tx = Transaction.from_string(ALICE_NOTIFICATION_TX_FOR_BOB)
        seed_bytes = bip39.mnemonic_to_seed(BOB_MNEMONIC)
        recipient_root = bip32.HDKey.from_seed(seed_bytes)

        # Strip the OP_RETURN output, leaving only the notification address output
        tx.vout = [
            vout for vout in tx.vout
            if not (vout.script_pubkey.data and vout.script_pubkey.data[0] == OPCODES.OP_RETURN)
        ]
        self.assertEqual(len(tx.vout), 1)

        self.assertIsNone(bip47.get_payment_code_from_notification_tx(tx, recipient_root))


    def test_get_payment_code_from_notification_tx_skips_non_extractable_input(self):
        """The function must skip inputs that don't expose a 33-byte compressed
            pubkey at the canonical position (e.g., P2SH/P2WSH/P2TR) and continue
            searching the remaining inputs."""
        tx = Transaction.from_string(ALICE_NOTIFICATION_TX_FOR_BOB)
        seed_bytes = bip39.mnemonic_to_seed(BOB_MNEMONIC)
        recipient_root = bip32.HDKey.from_seed(seed_bytes)

        # Prepend a synthetic input that mimics a taproot key-path spend: a
        # single-item witness, so witness.items[1] would IndexError. The original
        # P2PKH input from the test vector is now second; the loop must skip the
        # bad first input to find the good one (and use *its* outpoint when
        # unblinding the payload).
        bad_input = TransactionInput(
            txid=b"\x11" * 32,
            vout=0,
            script_sig=Script(b""),
            witness=Witness([b"\x00" * 64]),
        )
        tx.vin = [bad_input] + tx.vin

        self.assertEqual(
            bip47.get_payment_code_from_notification_tx(tx, recipient_root),
            ALICE_PAYMENT_CODE,
        )


    def test_get_payment_code_from_notification_tx_picks_up_p2sh_p2wpkh_witness_shape(self):
        """The pubkey extraction is shape-based: any segwit input whose witness is
            [sig, pubkey] is treated as the designated input. This includes nested
            P2SH-P2WPKH (not just bare P2WPKH).

            Prepend a synthetic input with both a non-empty script_sig (would-be
            P2SH redeem-script push) and a [sig, 33-byte-pubkey] witness, placed
            before the real P2PKH input. The loop selects the first input that
            yields a 33-byte compressed pubkey, so the synthetic one wins. Its
            (pubkey, outpoint) is unrelated to the actual blinding, so unblinding
            produces a result that does NOT recover ALICE_PAYMENT_CODE — the
            function returns either None (if the garbage x-coordinate isn't
            on-curve) or a non-canonical payment code. Either way, the assertion
            "not equal to ALICE_PAYMENT_CODE" proves the synthetic input was
            selected; if it had been skipped (treating P2SH-P2WPKH as
            unsupported), the loop would fall through to the real P2PKH input
            and return ALICE_PAYMENT_CODE.
        """
        tx = Transaction.from_string(ALICE_NOTIFICATION_TX_FOR_BOB)
        seed_bytes = bip39.mnemonic_to_seed(BOB_MNEMONIC)
        recipient_root = bip32.HDKey.from_seed(seed_bytes)

        # A valid 33-byte compressed pubkey unrelated to the actual notification tx.
        fake_pubkey = ec.PrivateKey(secret=b"\x42" * 32).get_public_key().serialize()
        self.assertEqual(len(fake_pubkey), 33)

        # Build a synthetic input shaped like a P2SH-P2WPKH spend:
        #   - script_sig: 22-byte push of the would-be P2WPKH redeem script
        #     (0x00 0x14 <20-byte hash160>). Hash content is irrelevant; the
        #     extraction code never inspects script_sig for segwit inputs.
        #   - witness: [<sig>, <pubkey>], same shape as bare P2WPKH.
        synthetic_input = TransactionInput(
            txid=b"\x22" * 32,
            vout=0,
            script_sig=Script(b"\x16\x00\x14" + b"\x00" * 20),
            witness=Witness([b"\x00" * 64, fake_pubkey]),
        )
        tx.vin = [synthetic_input] + tx.vin

        result = bip47.get_payment_code_from_notification_tx(tx, recipient_root)
        self.assertNotEqual(result, ALICE_PAYMENT_CODE)


    def test_get_payment_code_from_notification_tx_no_extractable_input(self):
        """If no input exposes a 33-byte compressed pubkey, the function returns
            None rather than raising."""
        tx = Transaction.from_string(ALICE_NOTIFICATION_TX_FOR_BOB)
        seed_bytes = bip39.mnemonic_to_seed(BOB_MNEMONIC)
        recipient_root = bip32.HDKey.from_seed(seed_bytes)

        # Convert the only input to a taproot-key-path-style input (single-item
        # witness, empty script_sig).
        only_input = tx.vin[0]
        only_input.script_sig = Script(b"")
        only_input.witness = Witness([b"\x00" * 64])

        self.assertIsNone(bip47.get_payment_code_from_notification_tx(tx, recipient_root))


    def test_get_payment_code_from_notification_tx_rejects_unsupported_version(self):
        """The OP_RETURN payload's first byte is a version byte; only version 1
            is currently supported. A non-1 version must cause the payload to be
            ignored (and with no payload identified, the function returns None).

            Also verifies that if a *second* OP_RETURN output with a valid v1
            payload is present, the loop continues past the unsupported one and
            still returns the correct payment code."""
        seed_bytes = bip39.mnemonic_to_seed(BOB_MNEMONIC)
        recipient_root = bip32.HDKey.from_seed(seed_bytes)

        tx = Transaction.from_string(ALICE_NOTIFICATION_TX_FOR_BOB)

        # Locate the OP_RETURN output and overwrite the payload's version byte.
        # data layout: [0]=OP_RETURN [1]=OP_PUSHDATA1 [2]=0x50 (len=80)
        #              [3]=version  [4]=0x00 ...
        original_op_return_script = None
        for vout in tx.vout:
            d = vout.script_pubkey.data
            if d and d[0] == OPCODES.OP_RETURN:
                original_op_return_script = vout.script_pubkey
                d = bytearray(d)
                d[3] = 2  # any value != 1
                vout.script_pubkey = Script(bytes(d))
                break
        self.assertIsNotNone(original_op_return_script)

        self.assertIsNone(bip47.get_payment_code_from_notification_tx(tx, recipient_root))

        # Now append a second OP_RETURN with the valid v1 payload after the corrupted one.
        # The loop must skip the unsupported version and pick up the valid payload,
        # returning Alice's payment code.
        tx.vout.append(TransactionOutput(value=0, script_pubkey=original_op_return_script))

        self.assertEqual(
            bip47.get_payment_code_from_notification_tx(tx, recipient_root),
            ALICE_PAYMENT_CODE,
        )


    def test_get_payment_code_from_notification_tx_unsupported_version_does_not_clobber_valid(self):
        """
            If a valid v1 OP_RETURN appears earlier in the output list and a later
            OP_RETURN carries an unsupported version, the unsupported one must not
            overwrite the previously-found valid payload.
        """
        seed_bytes = bip39.mnemonic_to_seed(BOB_MNEMONIC)
        recipient_root = bip32.HDKey.from_seed(seed_bytes)

        tx = Transaction.from_string(ALICE_NOTIFICATION_TX_FOR_BOB)

        # Build a v2-versioned copy of the original OP_RETURN script and append
        # it after the original (v1) OP_RETURN. Iteration order: notification
        # addr → valid v1 OP_RETURN → unsupported v2 OP_RETURN.
        for vout in tx.vout:
            d = vout.script_pubkey.data
            if d and d[0] == OPCODES.OP_RETURN:
                d2 = bytearray(d)
                d2[3] = 2  # unsupported version
                tx.vout.append(TransactionOutput(value=0, script_pubkey=Script(bytes(d2))))
                break

        self.assertEqual(
            bip47.get_payment_code_from_notification_tx(tx, recipient_root),
            ALICE_PAYMENT_CODE,
        )


    def test_get_payment_code_from_notification_tx_rejects_invalid_payload(self):
        """
            Per BIP-47, if the unblinded x-coordinate is not a valid secp256k1 point the
            payload must be ignored (return None).
        """
        # Sanity: unmodified vector tx still decodes correctly.
        tx = Transaction.from_string(ALICE_NOTIFICATION_TX_FOR_BOB)
        seed_bytes = bip39.mnemonic_to_seed(BOB_MNEMONIC)
        recipient_root = bip32.HDKey.from_seed(seed_bytes)
        self.assertEqual(
            bip47.get_payment_code_from_notification_tx(tx, recipient_root),
            ALICE_PAYMENT_CODE,
        )

        # Identify the OP_RETURN output and corrupt one byte of the blinded x-coordinate
        # region. Layout of the 83-byte data field:
        #   [0]=OP_RETURN [1]=OP_PUSHDATA1 [2]=0x50 (len=80)
        #   [3]=ver [4]=0x00 [5]=sign [6:38]=x [38:70]=chain_code [70:83]=zeros
        # Flipping a byte inside [6:38] alters the unblinded x-coordinate; with
        # overwhelming probability the result is not on-curve.
        tx2 = Transaction.from_string(ALICE_NOTIFICATION_TX_FOR_BOB)
        op_return_vout = None
        for vout in tx2.vout:
            d = vout.script_pubkey.data
            if d and d[0] == OPCODES.OP_RETURN:
                op_return_vout = vout
                break
        self.assertIsNotNone(op_return_vout)
        d = bytearray(op_return_vout.script_pubkey.data)
        d[7] ^= 0xFF
        op_return_vout.script_pubkey = Script(bytes(d))

        self.assertIsNone(bip47.get_payment_code_from_notification_tx(tx2, recipient_root))


    def test_end_to_end_notification_tx(self):
        """Alice should be able to construct a psbt that uses the utxo being spent to
            blind her payment code and include it as an OP_RETURN output that Bob can
            successfully unblind.

            Note: the above test used the already-constructed tx from the BIP-47 test
            vectors; this test demonstrates Alice's full psbt-to-tx construction
            process.
        """
        # Regtest initial psbt that spends one of Alice's utxos to Bob's notification
        #   address.
        ALICE_NOTIFICATION_BASE_PSBT = "cHNidP8BAHQCAAAAAbSCxQCModbVqGCXS5f5q5BbyrIPipQGLzRkUWlvMk41AAAAAAD9////AiICAAAAAAAAGXapFHhlOS7V9B6XfLmRNMuc4ixew5VliKyQFKgEAAAAABYAFMCPedocVwqxQv7WE3dtTEHFcgdeFwQAAAABAGkCAAAAAXVRckaobGUWT22l1cJgRaArprnVqrpKuIxmjoTenYzgAAAAABcWABQAOKoxxLYTkMskJhqVMhXE2L3mW/3///8BQxeoBAAAAAAWABR/yGzYyF9cb44byWc2v+DhQgtggBYEAAABAR9DF6gEAAAAABYAFH/IbNjIX1xvjhvJZza/4OFCC2CAIgYDdwO70Vy+5ob7m/irfdzOCIzKa2NpA+qZc8M4vUb/X/8YREM4d1QAAIABAACAAAAAgAAAAAAAAAAAAAAiAgPOQHgFgYW4Q0pSBPYgwA2DwbTSJsnO+ylBnsDILKIRpxhEQzh3VAAAgAEAAIAAAACAAQAAAAAAAAAA"
        psbt = PSBT.from_base64(ALICE_NOTIFICATION_BASE_PSBT)

        # Verify that this psbt is spending to Bob's notification addr
        self.assertEqual(psbt.outputs[0].script_pubkey.address(NETWORKS["regtest"]), BOB_NOTIFICATION_ADDR_REGTEST)

        # Extract the outpoint of the utxo Alice is spending: 32-byte txid in
        # reversed (little-endian) byte order + 4-byte vout (little-endian),
        # rendered as a 72-char hex string.
        vin = psbt.inputs[0].vin
        outpoint = (bytes(reversed(vin.txid)) + vin.vout.to_bytes(4, "little")).hex()

        # Derive Alice's private key for this utxo
        seed_bytes = bip39.mnemonic_to_seed(ALICE_MNEMONIC)
        alice_root = bip32.HDKey.from_seed(seed_bytes)
        prvkey = alice_root.derive("m/84'/1'/0'/0/0")  #  This utxo is Alice's first receive addr on regtest

        # Sanity check the prvkey
        self.assertEqual(p2wpkh(prvkey.get_public_key()).address(NETWORKS["regtest"]), psbt.inputs[0].script_pubkey.address(NETWORKS["regtest"]))

        # Use the utxo to blind Alice's payment code
        blinded_payload = bip47.get_blinded_payment_code(ALICE_PAYMENT_CODE_REGTEST, prvkey, outpoint, BOB_PAYMENT_CODE_REGTEST)

        # Build the additional psbt output with the blinded payload in an OP_RETURN
        # data = OP_RETURN OP_PUSHDATA1 (len of payload) <payload>
        raw_payload_data = unhexlify(blinded_payload)
        data = compact.to_bytes(OPCODES.OP_RETURN) + compact.to_bytes(OPCODES.OP_PUSHDATA1) + compact.to_bytes(len(raw_payload_data)) + raw_payload_data
        script = Script(data)
        output = OutputScope()
        output.script_pubkey = script
        output.value = 0
        psbt.outputs.append(output)

        # Alice signs and finalizes her psbt into a tx
        psbt.sign_with(alice_root)
        tx = finalizer.finalize_psbt(psbt)

        # Can Bob decode the payload in the tx?
        seed_bytes = bip39.mnemonic_to_seed(BOB_MNEMONIC)
        bob_root = bip32.HDKey.from_seed(seed_bytes)
        unblinded_payment_code = bip47.get_payment_code_from_notification_tx(tx, bob_root, coin=1, network=NETWORKS["regtest"])

        self.assertEqual(unblinded_payment_code, ALICE_PAYMENT_CODE_REGTEST)
