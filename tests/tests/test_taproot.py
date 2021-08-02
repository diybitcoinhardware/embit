from unittest import TestCase
from embit.bip32 import HDKey
from embit.networks import NETWORKS
from embit.script import p2tr, address_to_scriptpubkey
from embit.descriptor import Descriptor
from embit.psbt import DerivationPath, PSBT
from embit.ec import SchnorrSig, PublicKey
from embit.transaction import SIGHASH
from embit.psbtview import PSBTView
try:
	from io import BytesIO
except ImportError:
	from uio import BytesIO
from binascii import a2b_base64

KEY = "tprv8ZgxMBicQKsPf27gmh4DbQqN2K6xnXA7m7AeceqQVGkRYny3X49sgcufzbJcq4k5eaGZDMijccdDzvQga2Saqd78dKqN52QwLyqgY8apX3j"
ROOT = HDKey.from_string(KEY)
NET = NETWORKS["regtest"]

# tx without derivations. inp0 should be signed with addr0, inp1 with addr1
B64PSBT = "cHNidP8BAKYCAAAAAsBlMEaxkJwNZ6V+BZ06bKIb5q2CpF9sHDDj0/eJfzA1AAAAAAD+////kqnvuD+I8rLf8eELSAqvqBiEy5+IpOKpn/acu+gs0E8BAAAAAP7///8CAA4nBwAAAAAWABStYQVCeoRPwINTcqOPmDkTReYZVbjCyQEAAAAAIlEgDTyyEUjN1Oyxc6Z5xifyM3Kamy+Hrt0UdV86CeDMvf8AAAAAAAEAfQIAAAABRL1RocN1LnP4aONGuWFAJm0+Hej0SWAqlSlJ9caTP/gBAAAAAP7///8CAOH1BQAAAAAiUSBCFZNDTJDvmyVvyzL/thnwUyHGSdn0HDwInUIk/SHzmc4uGh4BAAAAFgAU1ZjhFjq1hmtoVb2+6O7jHrtqYsDLAAAAAQErAOH1BQAAAAAiUSBCFZNDTJDvmyVvyzL/thnwUyHGSdn0HDwInUIk/SHzmQABAH0CAAAAAcBlMEaxkJwNZ6V+BZ06bKIb5q2CpF9sHDDj0/eJfzA1AQAAAAD+////ArU9HxsBAAAAFgAUOGUymdaBcR3nQVoZ804qGf9H9iKA8PoCAAAAACJRIDrGIL80dDh9Y5xIBek776O9xpVrAtiuyiy8HXZSuTUZzAAAAAEBK4Dw+gIAAAAAIlEgOsYgvzR0OH1jnEgF6Tvvo73GlWsC2K7KLLwddlK5NRkAAAA="
B64SIGNED = "cHNidP8BAKYCAAAAAsBlMEaxkJwNZ6V+BZ06bKIb5q2CpF9sHDDj0/eJfzA1AAAAAAD+////kqnvuD+I8rLf8eELSAqvqBiEy5+IpOKpn/acu+gs0E8BAAAAAP7///8CAA4nBwAAAAAWABStYQVCeoRPwINTcqOPmDkTReYZVbjCyQEAAAAAIlEgDTyyEUjN1Oyxc6Z5xifyM3Kamy+Hrt0UdV86CeDMvf8AAAAAAAEAfQIAAAABRL1RocN1LnP4aONGuWFAJm0+Hej0SWAqlSlJ9caTP/gBAAAAAP7///8CAOH1BQAAAAAiUSBCFZNDTJDvmyVvyzL/thnwUyHGSdn0HDwInUIk/SHzmc4uGh4BAAAAFgAU1ZjhFjq1hmtoVb2+6O7jHrtqYsDLAAAAAQErAOH1BQAAAAAiUSBCFZNDTJDvmyVvyzL/thnwUyHGSdn0HDwInUIk/SHzmQEIQwFBApOkiV6PkijNENaddILURidJhTlnK3EnYT1zPnksBel0HHz4TyPDhF3VJA0RG480dr0yAy1l1agcbyZFKduv9QEAAQB9AgAAAAHAZTBGsZCcDWelfgWdOmyiG+atgqRfbBww49P3iX8wNQEAAAAA/v///wK1PR8bAQAAABYAFDhlMpnWgXEd50FaGfNOKhn/R/YigPD6AgAAAAAiUSA6xiC/NHQ4fWOcSAXpO++jvcaVawLYrsosvB12Urk1GcwAAAABASuA8PoCAAAAACJRIDrGIL80dDh9Y5xIBek776O9xpVrAtiuyiy8HXZSuTUZAQhDAUGRfNtYnHLUoAOM57UwVvcuqe0bUAiaO5PAnxp0AcyqdrV3d4Q8303FOCNp8SUDlbTs2idGiNqa+TCaUVQC6AmdAQAAAA=="

DERIVED_ADDRESSES = [
  "bcrt1pgg2exs6vjrhekft0eve0ldse7pfjr3jfm86pc0qgn4pzflfp7wvsc0kwqa",
  "bcrt1p8trzp0e5wsu86cuufqz7jwl05w7ud9ttqtv2aj3vhswhv54ex5vschn0cd",
  "bcrt1pvlk0rphxu63lj8rvp56r5984l68zmsl0hwxuusp2tgc3v23amxfqgk77mr",
  "bcrt1pxm8encfk3a2wukzj3766gqj78sppaqvjg4e403fx0f0zms4p0nasv3vvkn",
  "bcrt1pdq8ruhpcl0cfnwe4gwt4l5a44dmlmyw2jd2wynr5zkjdm9f6plwqrrzax3",
  "bcrt1pa92ls6t4msgucze8namtyzjxd4ttxaarpf7xxzxm9t0wya0aqyms972s7j",
  "bcrt1p2828a3nqsu5rsh4m0h0ymz4wunkldzwgv58zqzj4spxnxd09ql8sgjekvh",
  "bcrt1pkchswx6ygzf6rnn6wrxr8xqcmdjvw3nl0xcfxah0264uad8mkfjs7ze9ue",
  "bcrt1p35etfrlwmp0g4ycgvuz6qrc33zq66mq7yeuar0pawh68lae9nxps5kq5n5",
  "bcrt1pcwdyaf529a9qh38c2yttxxu2lgkwa2jpqt9rc259avqlxpf9d8hqmhxq26",
  "bcrt1p5s4g6v365uu54hsz6cvkn4l45fds2p6nw55ucnskhaz3kars0x2qnpef89",
]

class TaprootTest(TestCase):
    def test_script(self):
        for i, addr in enumerate(DERIVED_ADDRESSES):
            prv = ROOT.derive([0, i])
            pub = prv.to_public()
            sc = p2tr(pub)
            self.assertEqual(sc.address(NET), addr)
            self.assertEqual(address_to_scriptpubkey(addr), sc)

    def test_tweak(self):
        for i in range(10):
            prv = ROOT.child(i)
            pub = prv.to_public()
            tprv = prv.taproot_tweak(b"")
            tpub = pub.taproot_tweak(b"")
            self.assertEqual(tprv.sec(), tpub.sec())

    def test_descriptor(self):
        descstr = "tr(%s/0/*)" % ROOT.to_public()
        desc = Descriptor.from_string(descstr)
        self.assertTrue(desc.is_taproot)
        self.assertEqual(str(desc), descstr)
        for i, expected in enumerate(DERIVED_ADDRESSES):
            d = desc.derive(i)
            addr = d.address(NET)
            self.assertEqual(addr, expected)
            self.assertEqual(d.script_pubkey(), address_to_scriptpubkey(expected))

    def test_invalid(self):
        with self.assertRaises(Exception):
            Descriptor.from_string("wsh(tr(%s/0/*))" % ROOT)
        with self.assertRaises(Exception):
            Descriptor.from_string("sh(tr(%s/0/*))" % ROOT)
        # x-only is only allowed in tr
        Descriptor.from_string("tr(b4ca2da5380d9aeb5ca67e4f18c487ae9b668748517e12b788496f63765e2efa)")
        with self.assertRaises(Exception):
            Descriptor.from_string("wpkh(b4ca2da5380d9aeb5ca67e4f18c487ae9b668748517e12b788496f63765e2efa)")

    def test_sign_verify(self):
        unsigned = PSBT.from_string(B64PSBT)
        signed = PSBT.from_string(B64SIGNED)
        tx = unsigned.tx
        values = [inp.utxo.value for inp in unsigned.inputs]
        scripts = [inp.utxo.script_pubkey for inp in unsigned.inputs]
        for i, inp in enumerate(signed.inputs):
            wit = inp.final_scriptwitness.items[0]
            sig = SchnorrSig.parse(wit[:64])
            if len(wit) == 65:
                sighash = wit[64]
            else:
                sighash = SIGHASH.DEFAULT
            hsh = tx.sighash_taproot(i, script_pubkeys=scripts, values=values, sighash=sighash)
            pub = PublicKey.from_xonly(inp.utxo.script_pubkey.data[2:])
            self.assertTrue(pub.schnorr_verify(sig, hsh))
            # check signing and derivation
            prv = ROOT.derive([0, i])
            tweaked = prv.taproot_tweak(b"")
            self.assertEqual(pub.xonly(), tweaked.xonly())
            sig2 = tweaked.schnorr_sign(hsh)
            self.assertTrue(pub.schnorr_verify(sig2, hsh))
            self.assertEqual(sig, sig2)
            # sign with individual pks
            sigcount = unsigned.sign_with(prv.key, SIGHASH.ALL)
            self.assertEqual(sigcount, 1)
            self.assertEqual(unsigned.inputs[i].final_scriptwitness, signed.inputs[i].final_scriptwitness)

        for i, inp in enumerate(unsigned.inputs):
            prv = ROOT.derive([0, i])
            # remove final scriptwitness to test signing with root
            inp.final_scriptwitness = None
            # populate derivation
            inp.bip32_derivations[prv.key.get_public_key()] = DerivationPath(ROOT.my_fingerprint, [0, i])

        # test signing with root key
        counter = unsigned.sign_with(ROOT, SIGHASH.ALL)
        self.assertEqual(counter, 2)
        for inp1, inp2 in zip(unsigned.inputs, signed.inputs):
            self.assertEqual(inp1.final_scriptwitness, inp2.final_scriptwitness)
            inp1.final_scriptwitness = None

        # test signing with psbtview, unsigned already has derivations
        stream = BytesIO(unsigned.serialize())
        psbtv = PSBTView.view(stream, compress=False)
        sigs = BytesIO()
        sigcount = psbtv.sign_with(ROOT, sigs, SIGHASH.ALL)
        self.assertEqual(sigcount, len(unsigned.inputs))
        v = sigs.getvalue()
        # check sigs are in the stream
        for inp in signed.inputs:
            self.assertTrue(inp.final_scriptwitness.items[0] in v)
