from unittest import TestCase
from embit import bip21


# BIP21 test vectors
# https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki#examples

VECTORS_BIP21_VALID = [
    "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W",
    "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?label=Luke-Jr",
    "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=20.3&label=Luke-Jr",
    "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz",
    "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?somethingyoudontunderstand=50&somethingelseyoudontget=999",
]

VECTORS_BIP21_INVALID = [
    "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-somethingyoudontunderstand=50&req-somethingelseyoudontget=999",
]


class Bip21Test(TestCase):
    def test_bip21_valid_uris(self):
        """Test parsing of valid BIP21 URIs from the specification"""
        for i, uri_string in enumerate(VECTORS_BIP21_VALID):
            with self.subTest(i=i, uri=uri_string):
                # Should decode without raising an exception
                uri = bip21.BitcoinURI(uri_string)
                
                # Basic validation - all should have an address
                self.assertIsNotNone(uri.get_address())
                self.assertEqual(uri.get_address(), "175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W")

    def test_bip21_invalid_uris(self):
        """Test that invalid BIP21 URIs raise appropriate exceptions"""
        for i, uri_string in enumerate(VECTORS_BIP21_INVALID):
            with self.subTest(i=i, uri=uri_string):
                with self.assertRaises(bip21.BIP21Error):
                    bip21.BitcoinURI(uri_string)