from unittest import TestCase

from embit.bip32 import HDKey, parse_path


class Bip32PathTest(TestCase):
    def test_valid_paths(self):
        vectors = [
            ("m", []),
            ("m/", []),
            ("0/1", [0, 1]),
            ("m/0/1/", [0, 1]),
            ("m/44h/1H/0'/0/32", [0x8000002C, 0x80000001, 0x80000000, 0, 32]),
            ("m/2147483647", [0x7FFFFFFF]),
            ("m/2147483648", [0x80000000]),
            ("m/4294967295", [0xFFFFFFFF]),
            ("m/2147483647h", [0xFFFFFFFF]),
            ("m/2147483647H", [0xFFFFFFFF]),
            ("m/2147483647'", [0xFFFFFFFF]),
        ]
        for path, expected in vectors:
            self.assertEqual(parse_path(path), expected)

    def test_invalid_paths(self):
        paths = [
            "",
            "/0",
            "m//1/",
            "m/-1",
            "m/-10h",
            "m/-10H",
            "m/-10'",
            "m/2147483648h",
            "m/2147483648H",
            "m/2147483648'",
            "m/4294967296",
            "m/+1/",
            "m/ 1",
            "m/1  h",
            "m/1h ",
            "m/\n1/2",
            "m/h",
            "m/1.0",
            "m/\u0661",
        ]
        for path in paths:
            with self.assertRaises(ValueError):
                parse_path(path)

    def test_derive_rejects_negative_hardened_index(self):
        root = HDKey.from_seed(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
        with self.assertRaises(ValueError):
            root.derive("m/-10h")
