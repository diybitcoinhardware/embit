from unittest import TestCase
from embit import bip85, bip32
from binascii import unhexlify

ROOT = bip32.HDKey.from_string("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb")

VECTORS_BIP39 = [
    (12, 0, bip85.LANGUAGES.ENGLISH, "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"),
    (18, 0, bip85.LANGUAGES.ENGLISH, "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token"),
    (24, 0, bip85.LANGUAGES.ENGLISH, "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano"),
]

VECTORS_WIF = [
    (0, "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp"),
]

VECTORS_XPRV = [
    (0, "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX"),
]

VECTORS_HEX = [
    (64, 0, "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c"),
]

class Bip85Test(TestCase):
    def test_bip39(self):
        for num_words, index, lang, expected in VECTORS_BIP39:
            self.assertEqual(bip85.derive_mnemonic(ROOT, num_words, index, language=lang), expected)

    def test_wif(self):
        for idx, expected in VECTORS_WIF:
            self.assertEqual(bip85.derive_wif(ROOT, idx).wif(), expected)

    def test_xprv(self):
        for idx, expected in VECTORS_XPRV:
            self.assertEqual(bip85.derive_xprv(ROOT, idx).to_string(), expected)

    def test_hex(self):
        for num_bytes, idx, expected in VECTORS_HEX:
            self.assertEqual(bip85.derive_hex(ROOT, num_bytes, idx), unhexlify(expected))
