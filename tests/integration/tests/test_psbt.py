from unittest import TestCase, skip
from util.bitcoin import daemon
import random
import time
from embit.descriptor import Descriptor
from embit.descriptor.checksum import add_checksum
from embit.bip32 import HDKey
from embit.networks import NETWORKS
from embit.psbt import PSBT

wallet_prefix = "test"+random.randint(0,0xFFFFFFFF).to_bytes(4,'big').hex()
root = HDKey.from_string("tprv8ZgxMBicQKsPf27gmh4DbQqN2K6xnXA7m7AeceqQVGkRYny3X49sgcufzbJcq4k5eaGZDMijccdDzvQga2Saqd78dKqN52QwLyqgY8apX3j")
fgp = root.child(0).fingerprint.hex()
net = NETWORKS['regtest']

def random_wallet_name():
    return "test"+random.randint(0,0xFFFFFFFF).to_bytes(4,'big').hex()

class PSBTTest(TestCase):
    """Complete tests with Core on regtest - should catch problems with signing of transactions"""

    def sign_with_descriptor(self, d1, d2, root):
        rpc = daemon.rpc
        wname = random_wallet_name()
        # to derive addresses
        desc1 = Descriptor.from_string(d1)
        desc2 = Descriptor.from_string(d2)
        # recv addr 2
        addr1 = desc1.derive(2).address(net)
        # change addr 3
        addr2 = desc2.derive(3).address(net)

        # to add checksums
        d1 = add_checksum(str(d1))
        d2 = add_checksum(str(d2))
        rpc.createwallet(wname, True, True)
        w = daemon.wallet(wname)
        res = w.importmulti([{
                "desc": d1,
                "internal": False,
                "timestamp": "now",
                "watchonly": True,
                "range": 10,
            },{
                "desc": d2,
                "internal": True,
                "timestamp": "now",
                "watchonly": True,
                "range": 10,
            }],{"rescan": False})
        self.assertTrue(all([k["success"] for k in res]))
        wdefault = daemon.wallet()
        wdefault.sendtoaddress(addr1, 0.1)
        daemon.mine()
        psbt = w.walletcreatefundedpsbt([], [{wdefault.getnewaddress(): 0.002}], 0, {"includeWatching": True, "changeAddress": addr2}, True)
        unsigned = psbt["psbt"]
        psbt = PSBT.from_string(unsigned)
        psbt.sign_with(root)
        final = rpc.finalizepsbt(str(psbt))
        self.assertTrue(final["complete"])
        # test accept
        res = rpc.testmempoolaccept([final["hex"]])
        self.assertTrue(res[0]["allowed"])

    def test_wpkh(self):
        path = "84h/1h/0h"
        xpub = root.derive(f"m/{path}").to_public().to_string()
        d1 = f"wpkh([{fgp}/{path}]{xpub}/0/*)"
        d2 = f"wpkh([{fgp}/{path}]{xpub}/1/*)"

        self.sign_with_descriptor(d1, d2, root)

    def test_sh_wpkh(self):
        path = "49h/1h/0h"
        xpub = root.derive(f"m/{path}").to_public().to_string()
        d1 = f"sh(wpkh([{fgp}/{path}]{xpub}/0/*))"
        d2 = f"sh(wpkh([{fgp}/{path}]{xpub}/1/*))"

        self.sign_with_descriptor(d1, d2, root)

    def test_legacy(self):
        path = "44h/1h/0h"
        xpub = root.derive(f"m/{path}").to_public().to_string()
        d1 = f"pkh([{fgp}/{path}]{xpub}/0/*)"
        d2 = f"pkh([{fgp}/{path}]{xpub}/1/*)"

        self.sign_with_descriptor(d1, d2, root)
