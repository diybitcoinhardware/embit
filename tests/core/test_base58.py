# Tests adapted from base58:
# https://github.com/keis/base58/blob/master/test_base58.py

from embit.base58 import encode, decode, encode_check, decode_check
from unittest import TestCase


class Base58Test(TestCase):
    def test_simple_encode(self):
        data = encode(b"hello world")
        self.assertEqual(data, "StV1DL6CwTryKyV")

    def test_leadingz_encode(self):
        data = encode(b"\0\0hello world")
        self.assertEqual(data, "11StV1DL6CwTryKyV")

    def test_encode_empty(self):
        data = encode(b"")
        self.assertEqual(data, "")

    def test_simple_decode(self):
        data = decode("StV1DL6CwTryKyV")
        self.assertEqual(data, b"hello world")

    def test_leadingz_decode(self):
        data = decode("11StV1DL6CwTryKyV")
        self.assertEqual(data, b"\0\0hello world")

    def test_empty_decode(self):
        data = decode("1")
        self.assertEqual(data, b"\0")

    def test_check_identity(self):
        data = b"hello world"
        out = decode_check(encode_check(data))
        self.assertEqual(out, data)

    def test_check_failure(self):
        data = "3vQB7B6MrGQZaxCuFg4oH"
        self.assertRaises(ValueError, decode_check, data)

    def test_invalid_input(self):
        data = "xyz0"  # 0 is not part of the bitcoin base58 alphabet
        self.assertRaises(ValueError, decode, data)
