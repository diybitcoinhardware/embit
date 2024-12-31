"""
BIP-352 test vectors:
https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json
"""

from binascii import unhexlify
from unittest import TestCase

import pytest
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


LABEL_TEST_VECTORS = {
    "spend_priv_key": "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
    "scan_priv_key": "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
    "labels": [
        2,
        3,
        1001337
    ],
    "addresses": [
        "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjex54dmqmmv6rw353tsuqhs99ydvadxzrsy9nuvk74epvee55drs734pqq",
        "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqsg59z2rppn4qlkx0yz9sdltmjv3j8zgcqadjn4ug98m3t6plujsq9qvu5n",
        "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq7c2zfthc6x3a5yecwc52nxa0kfd20xuz08zyrjpfw4l2j257yq6qgnkdh5"
    ]
}


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


    def test_generate_labeled_silent_payment_address(self):
        """ Should generate the expected labeled silent payment addresses """
        spend_priv_key = PrivateKey(unhexlify(LABEL_TEST_VECTORS["spend_priv_key"]))
        scan_priv_key = PrivateKey(unhexlify(LABEL_TEST_VECTORS["scan_priv_key"]))
        for label, address in zip(LABEL_TEST_VECTORS["labels"], LABEL_TEST_VECTORS["addresses"]):
            sp_address = bip352.generate_labeled_silent_payment_address(scan_priv_key, spend_priv_key.get_public_key(), label)
            assert sp_address == address

        # Label may also be a string, but the bip does not provide any test vectors
        bip352.generate_labeled_silent_payment_address(scan_priv_key, spend_priv_key.get_public_key(), label="tenant 6102")

        # Label may also be passed in as bytes
        bip352.generate_labeled_silent_payment_address(scan_priv_key, spend_priv_key.get_public_key(), label="I am bytes".encode())

        with pytest.raises(Exception):
            # Label is required
            bip352.generate_labeled_silent_payment_address(scan_priv_key, spend_priv_key.get_public_key())
        
        with pytest.raises(Exception):
            # Label must be an int, str, or bytes
            bip352.generate_labeled_silent_payment_address(scan_priv_key, spend_priv_key.get_public_key(), label=1.0)
