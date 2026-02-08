"""Tests for network definitions and get_network function."""

import unittest
from embit import networks


class TestNetworks(unittest.TestCase):
    """Test Bitcoin network definitions."""

    def test_all_networks_present(self):
        """All expected Bitcoin networks should be defined."""
        expected = ["main", "test", "regtest", "signet", "testnet4"]
        for name in expected:
            self.assertIn(name, networks.NETWORKS)

    def test_testnet4_parameters(self):
        """testnet4 should have same parameters as testnet3."""
        test = networks.NETWORKS["test"]
        testnet4 = networks.NETWORKS["testnet4"]

        # Same address parameters
        self.assertEqual(testnet4["bech32"], test["bech32"])
        self.assertEqual(testnet4["bech32"], "tb")
        self.assertEqual(testnet4["p2pkh"], test["p2pkh"])
        self.assertEqual(testnet4["p2sh"], test["p2sh"])
        self.assertEqual(testnet4["wif"], test["wif"])

        # Same xpub/xprv versions
        self.assertEqual(testnet4["xpub"], test["xpub"])
        self.assertEqual(testnet4["xprv"], test["xprv"])
        self.assertEqual(testnet4["zpub"], test["zpub"])
        self.assertEqual(testnet4["zprv"], test["zprv"])

        # Same coin type
        self.assertEqual(testnet4["bip32"], test["bip32"])

    def test_get_network_direct(self):
        """get_network should return network by name."""
        main = networks.get_network("main")
        self.assertEqual(main["name"], "Mainnet")
        self.assertEqual(main["bech32"], "bc")

        test = networks.get_network("test")
        self.assertEqual(test["name"], "Testnet")
        self.assertEqual(test["bech32"], "tb")

    def test_get_network_testnet4(self):
        """get_network should handle testnet4."""
        testnet4 = networks.get_network("testnet4")
        self.assertIsNotNone(testnet4)
        self.assertEqual(testnet4["name"], "Testnet4")
        self.assertEqual(testnet4["bech32"], "tb")

    def test_get_network_unknown(self):
        """get_network should return None for unknown networks."""
        result = networks.get_network("unknown_network")
        self.assertIsNone(result)

    def test_mainnet_bech32(self):
        """Mainnet should use 'bc' prefix."""
        self.assertEqual(networks.NETWORKS["main"]["bech32"], "bc")

    def test_regtest_bech32(self):
        """Regtest should use 'bcrt' prefix."""
        self.assertEqual(networks.NETWORKS["regtest"]["bech32"], "bcrt")


if __name__ == "__main__":
    unittest.main()
