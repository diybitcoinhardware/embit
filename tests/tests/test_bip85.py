from unittest import TestCase
from embit import bip85, bip32
from binascii import unhexlify

ROOT = bip32.HDKey.from_string(
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
)

VECTORS_BIP39 = [
    (
        12,
        0,
        bip85.LANGUAGES.ENGLISH,
        "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose",
    ),
    (
        18,
        0,
        bip85.LANGUAGES.ENGLISH,
        "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token",
    ),
    (
        24,
        0,
        bip85.LANGUAGES.ENGLISH,
        "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano",
    ),
]

VECTORS_WIF = [
    (0, "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp"),
]

VECTORS_XPRV = [
    (
        0,
        "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX",
    ),
]

VECTORS_HEX = [
    (
        64,
        0,
        "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c",
    ),
]


class Bip85Test(TestCase):

    def test_derive_entropy(self):
        for app_index, path, expected in [
            (39, [0, 12, 0], unhexlify("6250b68daf746d12a24d58b4787a714bf1b58d69e4c2a466276fb16fe93dc52b6fac6b756894072241447cad56f6405ee326dbb473d2f5e943543590082927c0")),
            (2, [0], unhexlify("7040bb53104f27367f317558e78a994ada7296c6fde36a364e5baf206e502bb1f988080b7dd814e7ae7d6d83edbb6689886a560e165f4a740877cdf3beecacf8")),
            (32, [0], unhexlify("52405cd0dd21c5be78314a7c1a3c65ffd8d896536cc7dee3157db5824f0c92e2ead0b33988a616cf6a497f1c169d9e92562604e38305ccd3fc96f2252c177682")),
        ]:
            result = bip85.derive_entropy(ROOT, app_index, path)
            self.assertEqual(result, expected)

    def test_derive_entropy_fail_path_ge_hardened_index(self):
        with self.assertRaises(ValueError) as exc:
            bip85.derive_entropy(ROOT, 39, [bip32.HARDENED_INDEX + 1])
        self.assertEqual(str(exc.exception), "Path elements must be less than 2^31")

    def test_bip39(self):
        for num_words, index, lang, expected in VECTORS_BIP39:
            self.assertEqual(
                bip85.derive_mnemonic(ROOT, num_words, index, language=lang), expected
            )

    def test_bip39_fail_num_words(self):
        cases = [
            (11, 0, bip85.LANGUAGES.ENGLISH),
            (13, 0, bip85.LANGUAGES.ENGLISH),
            (15, 0, bip85.LANGUAGES.ENGLISH),
            (17, 0, bip85.LANGUAGES.ENGLISH),
            (19, 0, bip85.LANGUAGES.ENGLISH),
            (21, 0, bip85.LANGUAGES.ENGLISH),
            (23, 0, bip85.LANGUAGES.ENGLISH),
            (25, 0, bip85.LANGUAGES.ENGLISH),
        ]

        for num_words, index, lang in cases:
            with self.assertRaises(ValueError) as exc:
                bip85.derive_mnemonic(ROOT, num_words, index, language=lang)
            self.assertEqual(str(exc.exception), "Number of words must be 12, 18 or 24")

    def test_wif(self):
        for idx, expected in VECTORS_WIF:
            self.assertEqual(bip85.derive_wif(ROOT, idx).wif(), expected)

    def test_xprv(self):
        for idx, expected in VECTORS_XPRV:
            self.assertEqual(bip85.derive_xprv(ROOT, idx).to_string(), expected)

    def test_hex(self):
        for num_bytes, idx, expected in VECTORS_HEX:
            self.assertEqual(
                bip85.derive_hex(ROOT, num_bytes, idx), unhexlify(expected)
            )

    def test_hex_fail_num_bytes_ge_64(self):
        for num_bytes in [65, 100, 1000, 10000]:
            with self.assertRaises(ValueError) as exc:
                bip85.derive_hex(ROOT, num_bytes, 1)
            self.assertEqual(str(exc.exception), "Number of bytes must not exceed 64")

    def test_hex_fail_num_bytes_le_16(self):
        for num_bytes in [15, 14, 10, 0]:
            with self.assertRaises(ValueError) as exc:
                bip85.derive_hex(ROOT, num_bytes, 2)
            self.assertEqual(str(exc.exception), "Number of bytes must be at least 16")
