from embit import bip32, bip39, bip47
from unittest import TestCase


class Bip47Test(TestCase):
    """
        Test vectors from: https://gist.github.com/SamouraiDev/6aad669604c5930864bd
    """
    def test_get_payment_code(self):
        alice = "response seminar brave tip suit recall often sound stick owner lottery motion"
        seed_bytes = bip39.mnemonic_to_seed(alice)
        root = bip32.HDKey.from_seed(seed_bytes)
        alice_payment_code = bip47.get_payment_code(root)
        self.assertEqual(alice_payment_code, "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA")

        bob = "reward upper indicate eight swift arch injury crystal super wrestle already dentist"
        seed_bytes = bip39.mnemonic_to_seed(bob)
        root = bip32.HDKey.from_seed(seed_bytes)
        bob_payment_code = bip47.get_payment_code(root)
        self.assertEqual(bob_payment_code, "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97")

