from embit import bip32, bip39, bip47
from unittest import TestCase


"""
    Test vectors from: https://gist.github.com/SamouraiDev/6aad669604c5930864bd
"""
ALICE_MNEMONIC = "response seminar brave tip suit recall often sound stick owner lottery motion"
ALICE_PAYMENT_CODE = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA"

BOB_MNEMONIC = "reward upper indicate eight swift arch injury crystal super wrestle already dentist"
BOB_PAYMENT_CODE = "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97"


class Bip47Test(TestCase):

    def test_get_payment_code(self):
        # Provide `root` ourselves
        seed_bytes = bip39.mnemonic_to_seed(ALICE_MNEMONIC)
        root = bip32.HDKey.from_seed(seed_bytes)
        payment_code = bip47.get_payment_code(root)
        self.assertEqual(payment_code, ALICE_PAYMENT_CODE)

        # Use the convenience method
        payment_code = bip47.get_payment_code_from_mnemonic(ALICE_MNEMONIC)
        self.assertEqual(payment_code, ALICE_PAYMENT_CODE)

        # Provide `root` ourselves
        seed_bytes = bip39.mnemonic_to_seed(BOB_MNEMONIC)
        root = bip32.HDKey.from_seed(seed_bytes)
        payment_code = bip47.get_payment_code(root)
        self.assertEqual(payment_code, BOB_PAYMENT_CODE)

        # Use the convenience method
        payment_code = bip47.get_payment_code_from_mnemonic(BOB_MNEMONIC)
        self.assertEqual(payment_code, BOB_PAYMENT_CODE)

