from unittest import TestCase
from embit import networks
from embit.liquid import networks as liquid_networks


class NetworksTest(TestCase):
    """Tests for network configuration."""

    def test_testnet4_exists(self):
        """testnet4 should be a known network."""
        self.assertIn("testnet4", networks.NETWORKS)

    def test_testnet4_parameters(self):
        """testnet4 should use the same address formats as testnet3."""
        testnet4 = networks.NETWORKS["testnet4"]
        testnet = networks.NETWORKS["test"]
        
        # testnet4 uses tb1 addresses like testnet3
        self.assertEqual(testnet4["bech32"], "tb")
        self.assertEqual(testnet4["bech32"], testnet["bech32"])
        
        # Same BIP32 prefixes (tpub/tprv)
        self.assertEqual(testnet4["xpub"], testnet["xpub"])
        self.assertEqual(testnet4["xprv"], testnet["xprv"])
        
        # Same WIF prefix
        self.assertEqual(testnet4["wif"], testnet["wif"])
        
        # Same P2PKH/P2SH prefixes
        self.assertEqual(testnet4["p2pkh"], testnet["p2pkh"])
        self.assertEqual(testnet4["p2sh"], testnet["p2sh"])
        
        # Same coin type for BIP32 derivation
        self.assertEqual(testnet4["bip32"], testnet["bip32"])

    def test_testnet4_name(self):
        """testnet4 should have its own name."""
        testnet4 = networks.NETWORKS["testnet4"]
        self.assertEqual(testnet4["name"], "Testnet4")

    def test_liquid_get_network_testnet4(self):
        """liquid.networks.get_network('testnet4') should return Bitcoin testnet4, not elementsregtest."""
        net = liquid_networks.get_network("testnet4")
        
        # Should NOT fall back to elementsregtest
        self.assertNotEqual(net["bech32"], "ert")
        
        # Should return testnet4 with tb prefix
        self.assertEqual(net["bech32"], "tb")
        self.assertEqual(net["name"], "Testnet4")

    def test_liquid_get_network_known_networks(self):
        """liquid.networks.get_network should find all Bitcoin networks."""
        for name in ["main", "test", "regtest", "signet", "testnet4"]:
            net = liquid_networks.get_network(name)
            self.assertEqual(net["name"], networks.NETWORKS[name]["name"])

    def test_liquid_get_network_liquid_networks(self):
        """liquid.networks.get_network should find liquid-specific networks."""
        # These should return liquid networks, not fall back
        self.assertEqual(liquid_networks.get_network("liquidv1")["bech32"], "ex")
        self.assertEqual(liquid_networks.get_network("elementsregtest")["bech32"], "ert")
        self.assertEqual(liquid_networks.get_network("liquidtestnet")["bech32"], "tex")

    def test_liquid_get_network_unknown_fallback(self):
        """liquid.networks.get_network should fall back to elementsregtest for unknown networks."""
        net = liquid_networks.get_network("unknown_network_xyz")
        self.assertEqual(net["bech32"], "ert")
        self.assertEqual(net["name"], "Liquid Regtest")

    def test_all_networks_have_required_keys(self):
        """All networks should have the required configuration keys."""
        required_keys = ["name", "wif", "p2pkh", "p2sh", "bech32", "xprv", "xpub", "bip32"]
        
        for name, net in networks.NETWORKS.items():
            for key in required_keys:
                self.assertIn(key, net, f"Network '{name}' missing key '{key}'")
