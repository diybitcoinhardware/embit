from unittest import TestCase

from embit import bip32, bip39, bip47, script
from embit.transaction import Transaction


"""
    Test vectors from: https://gist.github.com/SamouraiDev/6aad669604c5930864bd
"""
ALICE_MNEMONIC = "response seminar brave tip suit recall often sound stick owner lottery motion"
ALICE_PAYMENT_CODE = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA"
ALICE_NOTIFICATION_ADDR = "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW"
ALICE_PAYS_BOB_ADDRS = [
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
]

BOB_MNEMONIC = "reward upper indicate eight swift arch injury crystal super wrestle already dentist"
BOB_PAYMENT_CODE = "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97"
BOB_NOTIFICATION_ADDR = "1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV"

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
    

    def test_get_notification_address(self):
        """Alice & Bob's derived notification addresses should match the test vectors in BIP-47"""
        self.assertEqual(bip47.get_notification_address(ALICE_PAYMENT_CODE), ALICE_NOTIFICATION_ADDR)
        self.assertEqual(bip47.get_notification_address(BOB_PAYMENT_CODE), BOB_NOTIFICATION_ADDR)


    def test_get_payment_address(self):
        """Alice's payment addresses to Bob's payment code should match the test vector addresses in BIP-47"""
        seed_bytes = bip39.mnemonic_to_seed(ALICE_MNEMONIC)
        payer_root = bip32.HDKey.from_seed(seed_bytes)

        for i, addr in enumerate(ALICE_PAYS_BOB_ADDRS):
            payment_addr = bip47.get_payment_address(
                payer_root=payer_root,
                recipient_payment_code=BOB_PAYMENT_CODE,
                index=i)
            self.assertEqual(addr, payment_addr)


    def test_get_receive_address(self):
        """Bob (the recipient) should be able to use Alice's payment code to generate the same addresses that Alice (the payer) generated"""
        seed_bytes = bip39.mnemonic_to_seed(BOB_MNEMONIC)
        recipient_root = bip32.HDKey.from_seed(seed_bytes)

        for i, addr in enumerate(ALICE_PAYS_BOB_ADDRS):
            payment_addr, spending_key = bip47.get_receive_address(
                recipient_root=recipient_root,
                payer_payment_code=ALICE_PAYMENT_CODE,
                index=i)
            self.assertEqual(addr, payment_addr)
            self.assertEqual(addr, script.p2pkh(spending_key.get_public_key()).address())

        # TODO: Verify that the spending_keys can successfully sign a tx for their associated payment_addr.


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
        self.assertEqual(bip47.get_payment_code_from_notification_tx(tx, other_root), None)
