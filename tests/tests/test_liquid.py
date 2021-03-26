from unittest import TestCase
from embit.util import secp256k1
from binascii import hexlify, unhexlify

class LiquidTest(TestCase):

    def test_value_commitment(self):
        # scalars in little endian
        vbf = bytes(reversed(unhexlify("8deb8cd6e79d8745a4cd13beb9222959f95f6c6b42b8ec524342b9c2879782e7")))
        # asset generator, blinded
        asset = bytes(reversed(unhexlify("6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d")))
        abf = bytes(reversed(unhexlify("15804b1a8aacaa52163a5e3a42182cb3a26cafbfe4e1d91c06c4adab4472695f")))
        # sec-serialized point
        expected = unhexlify("0b1c079dafd9725ddfd63eed4ad70e71113fa5158aa59ed5154c64627d42f1b342")

        gen = secp256k1.generator_generate_blinded(asset, abf)
        sec = secp256k1.generator_serialize(gen)
        self.assertEqual(sec, expected)

        # real value in satoshi
        value = round(2**62)
        # commitment
        commit = secp256k1.pedersen_commit(vbf, value, gen)
        sec = secp256k1.pedersen_commitment_serialize(commit)
        # commitments, sec-serialized
        # value_commitment = unhexlify("09d74784ca1f86fdb07726a9574f054946e4d8c547bfc42ee56b930f8f50af9da1")
        value_commitment = unhexlify("09e61ce0a80989c0223890645d29641a774dd9a57108b6e726d1f24cefbca1d9e1")
        self.assertEqual(sec, value_commitment)

        # nonce_commitment = bytes.fromhex("03b6627cedfa95a7b9200a3fb1041011e05a86968d873f74540d0cf5491c838df3")
        # some crazy proof
        # surjection_proof = bytes.fromhex("01000119b734c68b72ccb75288c919ecb976671dd7d17385d968f96215ca5161bd99eb913740ff7dd29a196b580068e058898c1ec7ecabfe147198fb988551a21580cd")
