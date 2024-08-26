"""
BIP-352 test vectors:
https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json
"""

from binascii import unhexlify
from unittest import TestCase
from embit import bip352
from embit.ec import PrivateKey
from embit.networks import NETWORKS


BASIC_TEST_VECTORS = [
    {
        "spend_priv_key": "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
        "scan_priv_key": "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
        "sp_address": "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"
    },
    {
        "spend_priv_key": "0000000000000000000000000000000000000000000000000000000000000001",
        "scan_priv_key": "0000000000000000000000000000000000000000000000000000000000000002",
        "sp_address": "sp1qqtrqglu5g8kh6mfsg4qxa9wq0nv9cauwfwxw70984wkqnw2uwz0w2qnehen8a7wuhwk9tgrzjh8gwzc8q2dlekedec5djk0js9d3d7qhnq6lqj3s"
    }
]


class BIP352Test(TestCase):
    def test_generate_silent_payment_address(self):
        """ Should generate the expected silent payment address """
        for test_vector in BASIC_TEST_VECTORS:
            spend_priv_key = PrivateKey(unhexlify(test_vector["spend_priv_key"]))
            scan_priv_key = PrivateKey(unhexlify(test_vector["scan_priv_key"]))
            sp_address = bip352.generate_silent_payment_address(scan_priv_key.get_public_key(), spend_priv_key.get_public_key())
            assert sp_address == test_vector["sp_address"]


    def test_generate_silent_payment_address_for_network(self):
        """ Test network silent payment addrs should start with "tsp" """
        test_networks = [k for k in NETWORKS.keys() if k != "main"]
        scan_pubkey = PrivateKey(unhexlify(BASIC_TEST_VECTORS[0]["spend_priv_key"])).get_public_key()
        spend_pubkey = PrivateKey(unhexlify(BASIC_TEST_VECTORS[0]["scan_priv_key"])).get_public_key()

        for network in test_networks:
            payment_addr = bip352.generate_silent_payment_address(scan_pubkey, spend_pubkey, network=network)
            assert payment_addr.startswith("tsp")
