from unittest import TestCase, skip
from util.liquid import daemon
import random
import time
import os

from embit.liquid.descriptor import LDescriptor as Descriptor
from embit.descriptor.checksum import add_checksum
from embit.bip32 import HDKey
from embit.liquid.networks import get_network
from embit.liquid.pset import PSET as PSBT
from embit.liquid.transaction import LSIGHASH
from embit.liquid.finalizer import finalize_psbt
from embit.liquid.addresses import addr_decode
from embit.ec import PrivateKey

wallet_prefix = "test"+random.randint(0,0xFFFFFFFF).to_bytes(4,'big').hex()
root = HDKey.from_string("tprv8ZgxMBicQKsPf27gmh4DbQqN2K6xnXA7m7AeceqQVGkRYny3X49sgcufzbJcq4k5eaGZDMijccdDzvQga2Saqd78dKqN52QwLyqgY8apX3j")
fgp = root.child(0).fingerprint.hex()
net = get_network('elreg')

def random_wallet_name():
    return "test"+random.randint(0,0xFFFFFFFF).to_bytes(4,'big').hex()

class PSETTest(TestCase):
    """Complete tests with Core on regtest - should catch problems with signing of transactions"""

    def sign_with_descriptor(self, d1, d2, root, selfblind=False):
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
        rpc.createwallet(wname, True, True, "", False, True, False)
        w = daemon.wallet(wname)
        res = w.importdescriptors([{
                "desc": d1,
                "active": True,
                "internal": False,
                "timestamp": "now",
            },{
                "desc": d2,
                "active": True,
                "internal": True,
                "timestamp": "now",
            }])
        self.assertTrue(all([k["success"] for k in res]))
        bpk = b"1"*32
        w.importmasterblindingkey(bpk.hex())
        addr1 = w.getnewaddress()
        wdefault = daemon.wallet()
        wdefault.sendtoaddress(addr1, 0.1)
        daemon.mine()
        waddr = wdefault.getnewaddress()
        psbt = w.walletcreatefundedpsbt([], [{waddr: 0.002}], 0, {"includeWatching": True, "changeAddress": addr1, "fee_rate": 1}, True)
        unsigned = psbt["psbt"]

        # fix blinding change address
        tx = PSBT.from_string(unsigned)
        _, bpub = addr_decode(addr1)
        if not tx.outputs[psbt["changepos"]].blinding_pubkey:
            tx.outputs[psbt["changepos"]].blinding_pubkey = bpub.sec()
            unsigned = str(tx)

        # blind with custom message
        if selfblind:
            unblinded_psbt = PSBT.from_string(unsigned)
            # generate all blinding stuff
            unblinded_psbt.unblind(PrivateKey(bpk)) # get values and blinding factors for inputs
            unblinded_psbt.blind(os.urandom(32)) # generate all blinding factors etc
            for i, out in enumerate(unblinded_psbt.outputs):
                if unblinded_psbt.outputs[i].blinding_pubkey:
                    out.reblind(b"1"*32, unblinded_psbt.outputs[i].blinding_pubkey, b"test message")

            # remove stuff that Core doesn't like
            for inp in unblinded_psbt.inputs:
                inp.value = None
                inp.asset = None
                inp.value_blinding_factor = None
                inp.asset_blinding_factor = None

            for out in unblinded_psbt.outputs:
                if out.is_blinded:
                    out.asset = None
                    out.asset_blinding_factor = None
                    out.value = None
                    out.value_blinding_factor = None

            psbt = unblinded_psbt
        # use rpc to blind transaction
        else:
            try: # master branch
                blinded = w.blindpsbt(unsigned)
            except:
                blinded = w.walletprocesspsbt(unsigned)['psbt']

            psbt = PSBT.from_string(blinded)

        psbt.sign_with(root)
        final = rpc.finalizepsbt(str(psbt))
        if final["complete"]:
            raw = final["hex"]
        else:
            print("WARNING: finalize failed, trying with embit")
            tx = finalize_psbt(psbt)
            raw = str(tx)
        # test accept
        res = rpc.testmempoolaccept([raw])
        self.assertTrue(res[0]["allowed"])
        if selfblind:
            # check we can reblind all outputs
            import json
            raw = w.unblindrawtransaction(raw)["hex"]
            decoded = w.decoderawtransaction(raw)
            self.assertEqual(len(decoded["vout"]) - sum([int("value" in out) for out in decoded["vout"]]), 1)

    def test_wpkh(self):
        path = "84h/1h/0h"
        xpub = root.derive(f"m/{path}").to_public().to_string()
        d1 = f"wpkh([{fgp}/{path}]{xpub}/0/*)"
        d2 = f"wpkh([{fgp}/{path}]{xpub}/1/*)"

        self.sign_with_descriptor(d1, d2, root)

    # def test_sh_wpkh(self):
    #     path = "49h/1h/0h"
    #     xpub = root.derive(f"m/{path}").to_public().to_string()
    #     d1 = f"sh(wpkh([{fgp}/{path}]{xpub}/0/*))"
    #     d2 = f"sh(wpkh([{fgp}/{path}]{xpub}/1/*))"

    #     self.sign_with_descriptor(d1, d2, root)

    # def test_legacy(self):
    #     path = "44h/1h/0h"
    #     xpub = root.derive(f"m/{path}").to_public().to_string()
    #     d1 = f"pkh([{fgp}/{path}]{xpub}/0/*)"
    #     d2 = f"pkh([{fgp}/{path}]{xpub}/1/*)"

    #     self.sign_with_descriptor(d1, d2, root)

    def test_selfblind(self):
        path = "84h/1h/0h"
        xpub = root.derive(f"m/{path}").to_public().to_string()
        d1 = f"wpkh([{fgp}/{path}]{xpub}/0/*)"
        d2 = f"wpkh([{fgp}/{path}]{xpub}/1/*)"

        self.sign_with_descriptor(d1, d2, root, selfblind=True)
