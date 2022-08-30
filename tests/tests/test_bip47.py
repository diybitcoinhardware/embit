from unittest import TestCase

from embit import bip32, bip39, bip47, script, ec
from embit.networks import NETWORKS
from embit.transaction import Transaction
from binascii import hexlify, unhexlify


"""
    Test vectors from: https://gist.github.com/SamouraiDev/6aad669604c5930864bd
"""
ALICE_MNEMONIC = "response seminar brave tip suit recall often sound stick owner lottery motion"
ALICE_PAYMENT_CODE = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA"
ALICE_PAYMENT_CODE_REGTEST = "PM8TJcUtZbTqYoGWcNAnaYDkAzA1cLq6gQV4aPJ3N5jydgmTHUr5UFK74CU58mdL6V8pVo3JJ8JsJFJzriZSGMj27ujJ3jxwFUQwi49ox3Cfai4SG5rk"
ALICE_NOTIFICATION_ADDR = "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW"
ALICE_NOTIFICATION_ADDR_REGTEST = "mod1FsW4dsVRod4ZVRR3D3ovY97SxSjJwk"
ALICE_NOTIFICATION_INPUT_PRIVATE_KEY = "Kx983SRhAZpAhj7Aac1wUXMJ6XZeyJKqCxJJ49dxEbYCT4a1ozRD"
ALICE_NOTIFICATION_INPUT_OUTPOINT = "86f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c01000000"
ALICE_NOTIFICATION_BLINDED_PAYLOAD = "010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b00000000000000000000000000"

"""
    Mainnet p2pkh from BIP-47 test vectors, remaining addrs generated from:
    https://bitcoiner.guide/seed
"""
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


    def test_get_payment_code_from_notification_tx(self):
        """Bob (the recipient) should be able to decode Alice's payment code from her notification tx"""
        tx = Transaction.from_string(ALICE_NOTIFICATION_TX_FOR_BOB)
        seed_bytes = bip39.mnemonic_to_seed(BOB_MNEMONIC)
        recipient_root = bip32.HDKey.from_seed(seed_bytes)

        payer_payment_code = bip47.get_payment_code_from_notification_tx(tx, recipient_root)
        self.assertEqual(payer_payment_code, ALICE_PAYMENT_CODE)

        # Any other root should fail
        seed_bytes = bip39.mnemonic_to_seed("abandon " * 11 + "about")
        other_root = bip32.HDKey.from_seed(seed_bytes)
        self.assertTrue(bip47.get_payment_code_from_notification_tx(tx, other_root) is None)
