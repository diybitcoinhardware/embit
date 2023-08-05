from unittest import TestCase
from embit.bip32 import HDKey
from embit.networks import NETWORKS
from embit.script import p2tr, address_to_scriptpubkey
from embit.descriptor import Descriptor
from embit.psbt import DerivationPath, PSBT
from embit.psbtview import PSBTView
from embit.ec import SchnorrSig, PublicKey
from embit.transaction import SIGHASH
from io import BytesIO
from binascii import unhexlify

KEY = "tprv8ZgxMBicQKsPf27gmh4DbQqN2K6xnXA7m7AeceqQVGkRYny3X49sgcufzbJcq4k5eaGZDMijccdDzvQga2Saqd78dKqN52QwLyqgY8apX3j"
ROOT = HDKey.from_string(KEY)
NET = NETWORKS["regtest"]

# tx without derivations. inp0 should be signed with addr0, inp1 with addr1
# TODO: Update to a test vector that includes `PSBT_IN_TAP_BIP32_DERIVATION`
# and test with full signing flow.
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

# Test vector(s) from BIP-371:
# Case: PSBT with one P2TR key only input with internal key and its derivation path (includes `PSBT_IN_TAP_BIP32_DERIVATION` and `PSBT_IN_TAP_INTERNAL_KEY`)
TAPROOT_01 = "70736274ff010052020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff0148e6052a01000000160014768e1eeb4cf420866033f80aceff0f9720744969000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a07572116fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa2321900772b2da75600008001000080000000800100000000000000011720fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa232002202036b772a6db74d8753c98a827958de6c78ab3312109f37d3e0304484242ece73d818772b2da7540000800100008000000080000000000000000000"

# Test vectors generated from master branch of Bitcoin Core
KEY_A = HDKey.from_string("xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu")
# psbt with taproot derivations
TAP_PSBTS = [
    # tr(A)
    "cHNidP8BAH0CAAAAAcvX2qbTVRs2ba+B8Jxem6oHsheRltrKWpdsT8EpTnBtAQAAAAD9////AvJJXQUAAAAAIlEgdeZfiD3lhycx2Y6ob18IYvCSOdDpsA9J9ZIGnBhNAqKAlpgAAAAAABYAFHAkanlSWSwxrcCwYWjATxOt1uVpAAAAAAABASsA4fUFAAAAACJRIDuCsrKpGFMV2m+A2l8G0EQNil4UV/qTOHwtkZyG7IeGIRZVNVyoPJc/HZfODjhDyF14kFrxa03FMbxIjlchLSMBFhkAc8XaClYAAIABAACAAAAAgAAAAAAAAAAAARcgVTVcqDyXPx2Xzg44Q8hdeJBa8WtNxTG8SI5XIS0jARYAAQUgIOuQUAaLATvePSBNtZrF2yoceKiqJQc/vy561J0FFcYBBgAhByDrkFAGiwE73j0gTbWaxdsqHHioqiUHP78uetSdBRXGGQBzxdoKVgAAgAEAAIAAAACAAQAAAAEAAAAAAA==",
    # tr(A,{{pk(B),pk(C)},pk(D)})
    "cHNidP8BAH0CAAAAAUAaxszo/duEBuHMtAC7DT2fNdfsnS4wy8vF3hAB/UlJAAAAAAD9////AoCWmAAAAAAAFgAUcCRqeVJZLDGtwLBhaMBPE63W5WnySV0FAAAAACJRIBrRhQ5SjnkT5tE70JEBxp9xkb4uBIHRIzkxac7HP5ZTAAAAAAABASsA4fUFAAAAACJRIFKH/tGO0Q0s2Smklua645o2AiaKUkBJnG3YDvfOcbbVQhXBVTVcqDyXPx2Xzg44Q8hdeJBa8WtNxTG8SI5XIS0jARZUoQdnQp/8bMLMLulMq6QGi4+kememhbEVYTvrM2DmDyMgBB+2r5b0+qaabbiKXfGsCCZ/X5i6EoOa82ErtH5BigCswGIVwVU1XKg8lz8dl84OOEPIXXiQWvFrTcUxvEiOVyEtIwEWFGi48vIp9D+FdjTmg1ubdkSHIVzdfVMACq33siHM79pMxC/7Yq3dbpesX7UJSDHq71fmbAYALaDQdod4fu5JsSMgBgozO1jxe6uPd2hvHYlLTaKei2UIjBpBGIJfyCL/os6swGIVwVU1XKg8lz8dl84OOEPIXXiQWvFrTcUxvEiOVyEtIwEWMbziDCAn/bPsPqCxK0QUbVF34xa8bETwhZ1jFzu+SvNMxC/7Yq3dbpesX7UJSDHq71fmbAYALaDQdod4fu5JsSMgtpzeELVS/INwpBPZEQhNBIUStilyPL6A7W14NH4UZeSswCEWBB+2r5b0+qaabbiKXfGsCCZ/X5i6EoOa82ErtH5BigA5AUzEL/tird1ul6xftQlIMervV+ZsBgAtoNB2h3h+7kmxAgjLd1YAAIABAACAAAAAgAAAAAAAAAAAIRYGCjM7WPF7q493aG8diUtNop6LZQiMGkEYgl/IIv+izjkBMbziDCAn/bPsPqCxK0QUbVF34xa8bETwhZ1jFzu+SvNH/BuhVgAAgAEAAIAAAACAAAAAAAAAAAAhFlU1XKg8lz8dl84OOEPIXXiQWvFrTcUxvEiOVyEtIwEWGQBzxdoKVgAAgAEAAIAAAACAAAAAAAAAAAAhFrac3hC1UvyDcKQT2REITQSFErYpcjy+gO1teDR+FGXkOQEUaLjy8in0P4V2NOaDW5t2RIchXN19UwAKrfeyIczv2vt8HxFWAACAAQAAgAAAAIAAAAAAAAAAAAEXIFU1XKg8lz8dl84OOEPIXXiQWvFrTcUxvEiOVyEtIwEWARggyx1Uf/jQ00tM3UjsFjZveDZgMfHHVAqzX2EeP2HYuVgAAAEFICDrkFAGiwE73j0gTbWaxdsqHHioqiUHP78uetSdBRXGAQZvAcAiIBzPJ1Xc+LktQvZ2DfUHF8ZjLstb2yy8knw6sWGa6npzrALAIiB7XX2FRbhtQQ1OMFHZrKQJgm9Uy11VIkks1y6DlEvafqwCwCIg0OVDwS5pv86EQus8QaNW31/onw7JQJ1aEgD4mu/9Iv2sIQcczydV3Pi5LUL2dg31BxfGYy7LW9ssvJJ8OrFhmup6czkBf88QfvUR3XwjmSYdA3uHV+ve/BhYs0/r70731kheDW8CCMt3VgAAgAEAAIAAAACAAQAAAAEAAAAhByDrkFAGiwE73j0gTbWaxdsqHHioqiUHP78uetSdBRXGGQBzxdoKVgAAgAEAAIAAAACAAQAAAAEAAAAhB3tdfYVFuG1BDU4wUdmspAmCb1TLXVUiSSzXLoOUS9p+OQGzJ3RT0eho23a5cca/2jX8AETEICnTMTP12ajR30czFEf8G6FWAACAAQAAgAAAAIABAAAAAQAAACEH0OVDwS5pv86EQus8QaNW31/onw7JQJ1aEgD4mu/9Iv05ATfGpiWBWMHLfN4FazQuz2SBvTDiVWvd3kqLsLZGpyDW+3wfEVYAAIABAACAAAAAgAEAAAABAAAAAA==",
]
TAP_SIGS = [
    (
        unhexlify("6f7f1255071fb5a103b5a4d3e5e295d19e9701e58fa1c457e92733c53ed16804f1036c90f30f6c4753a884c2be8b7d4a7c30a2a86dbfb0e8010bdf7064fd70f7"), # sig of keyA
    ),
    (
        unhexlify("0574a2735988c4c8bd866ac546ae3f8a29f19a9596742892638c53f3b593269975135f0c58b2db945723e109db4111f6789e2abd37d2de82e94b8af47de63bda"), # A
    ),
]
# tr(A,{pk(B),and_v(v:pk(C),pk(D))})
TAPTREE_PSBT = "cHNidP8BAH0CAAAAAeIMcyOBWNnbIqmCIqa0QL9JAwsaDV4HT6+Xv4wJjL17AAAAAAD9////AoCWmAAAAAAAFgAUvSBc5eYHgqHxk7upi3kv5gA/1O3ySV0FAAAAACJRIGNAxXuNUt0BJ6ByFOx9/al93vWen39D6Af7ss1QjlwKAAAAAAABASsA4fUFAAAAACJRIHC7J82blWTnJH9Nl/qeHS97m2KxuBv3L2g58EhgndRRQhXBfy5RDYbr51o4fyQYpNrWWE20ga8PKn5tEtuU8YRHEvhnBFg9xpf/3wPhiU5hrocTD1m9uX9M4MVKhILWLawC70UgUEM1JJofA2CVc9wW77clA2DWZfBnpHMi6GWAVIiEvz2tIK6FHC9E+O2EZBy/b2qVNwJHDf4+QsYN5obNcIcKAP18rMBCFcF/LlENhuvnWjh/JBik2tZYTbSBrw8qfm0S25TxhEcS+J35N4fUhRXmtCF4ZSZhqoN56GqlIBK0Gj/iYJQTJDRCIyBziRZlLMwPXQz69ZgIm6VuAY8hTHxOJrwUh+1pDTGcDazAIRZQQzUkmh8DYJVz3BbvtyUDYNZl8GekcyLoZYBUiIS/PS0Bnfk3h9SFFea0IXhlJmGqg3noaqUgErQaP+JglBMkNELPWtqTAAAAAAAAAAAhFnOJFmUszA9dDPr1mAibpW4BjyFMfE4mvBSH7WkNMZwNLQFnBFg9xpf/3wPhiU5hrocTD1m9uX9M4MVKhILWLawC78xSxyIAAAAAAAAAACEWfy5RDYbr51o4fyQYpNrWWE20ga8PKn5tEtuU8YRHEvgNAHNc6iAAAAAAAAAAACEWroUcL0T47YRkHL9vapU3AkcN/j5Cxg3mhs1whwoA/XwtAZ35N4fUhRXmtCF4ZSZhqoN56GqlIBK0Gj/iYJQTJDRCDAm+LgAAAAAAAAAAARcgfy5RDYbr51o4fyQYpNrWWE20ga8PKn5tEtuU8YRHEvgBGCCUd6Gt2gcmsS/p11C8qpWk79PycyZyAFfM9UNU20W7+wAAAQUg+Du+Rd0qJvYodMsO7j4IVEu8ULoV8jbI1xSbhvot3JEBBmwBwEQgSo5aG71puZDqSiCzIG8zB0pxRZ/Wwkomtl/qpfij37GtIOZJwZtZajmvPLeCviLhGhtqGqLhbezFzxyiqQ9rMrwarAHAIiCKbSCtGMYmKiLS7Ts2At4JPCw1D068SEAP4iuSS1r6pKwhB0qOWhu9abmQ6kogsyBvMwdKcUWf1sJKJrZf6qX4o9+xLQFy0Iqb4ksGrxmHa6MqKmavcuGFR40PfYWk3m4jZLMIHc9a2pMBAAAAAAAAACEHim0grRjGJioi0u07NgLeCTwsNQ9OvEhAD+Irkkta+qQtAd4SDZI0Q0pda4MXoWhUUigZ4oroff9guQq9Mb0CBc4yzFLHIgEAAAAAAAAAIQfmScGbWWo5rzy3gr4i4Robahqi4W3sxc8coqkPazK8Gi0BctCKm+JLBq8Zh2ujKipmr3LhhUeND32FpN5uI2SzCB0MCb4uAQAAAAAAAAAhB/g7vkXdKib2KHTLDu4+CFRLvFC6FfI2yNcUm4b6LdyRDQBzXOogAQAAAAAAAAAA"

TAPTREE_KEYS = [
    HDKey.from_string(k)
    for k in [
        "tprv8ZgxMBicQKsPdiNEPCogjnPGeK4zgUpZGGEP2k2hhiANSpPuUWGVWb6WCQhjSPDn7Nz2u9kq9U1Z1bz6ZVpYL4w3kudYESRMrTprfKzzNyd",
        "tprv8ZgxMBicQKsPeDCydL6eDyVohN3tLNU4MWrrFBmKkSHUE46mWUQ6YzLAmW57JPiofGLkW2ZCPbtC4NtoKBGWDG9cJhx6d9UhuJdUbFbD36w",
        "tprv8ZgxMBicQKsPeYcQMuAVda55CQtNHjWQmA33U9XXxPwpnxGHWSe9xoqmJRj4p1AJ8eXDDt82U4vJuvGETigWHYobjXCxpdCqRDsrqdUEpSt",
        "tprv8ZgxMBicQKsPdabEfXZrBoDe7V2gmahYeASskjJCrpNLoeLuaDq6kzVXbceiQQAoacFDsB7oeek1XinDZy73A6N56z1mKFJv2o7f6EA8Vhn",
    ]
]
TAPTREE_SIGS = [
    unhexlify("fd2877b89797991d0e237f466a917a5300944f6fb1453b576763ef76e5d1140816d4ec923b36975b859cb744a85286cd0d15a6f7c0ed15f9d03852c7716b3207"), # internal
    unhexlify("5fd88ed2ce431b003ce2b0e233a3b7870514b130e700b612a4d86fedeb603657ac88e2f4f290ee7ed16e23f6d27f717a5447acdbea5e72d16497a29a4ea46ca6"), # keyA
    unhexlify("fe9f994315faa9caab4e41d78b0200ca19fd3c735ce7d88e879b0da0b7e1f4dd31f877b6529700f463670f1a6f6ea217f6dfc596cf8c55e78b42b70e3491aac3"), # keyB
    unhexlify("d09a024358e7f609a0c3dfb94ac852c3f20859784f18911b5ec4cbc8c5ebf4a3642254519b47368fa1b2df75e10c56b77e7f9f34157335c2bc814106e544077c"), # keyC
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

        # TODO: Won't need to populate derivation when a psbt with Taproot fields is
        # used for this test.
        for i, inp in enumerate(unsigned.inputs):
            prv = ROOT.derive([0, i])
            # remove final scriptwitness to test signing with root
            inp.final_scriptwitness = None
            # populate derivation; Taproot signing expects X-only pubkeys
            inp.bip32_derivations[PublicKey.from_xonly(prv.key.xonly())] = DerivationPath(ROOT.my_fingerprint, [0, i])

        # test signing with root key
        counter = unsigned.sign_with(ROOT, SIGHASH.ALL)
        self.assertEqual(counter, 2)
        for inp1, inp2 in zip(unsigned.inputs, signed.inputs):
            self.assertEqual(inp1.final_scriptwitness, inp2.final_scriptwitness)

            # Reset input for final part of test
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


    def test_taproot_internal_keyspend(self):
        """Should parse Taproot `PSBT_IN_TAP_BIP32_DERIVATION` field and populate 
            `taproot_bip32_derivations` in each input. """
        psbt_bytes = unhexlify(TAPROOT_01)
        psbt_act = PSBT.parse(psbt_bytes)
        inp = psbt_act.inputs[0]
        self.assertTrue(inp.is_taproot)

        # Should have extracted: X-only pubkey, ([leaf_hashes], DerivationPath)
        # from `PSBT_IN_TAP_BIP32_DERIVATION`
        self.assertTrue(len(inp.taproot_bip32_derivations) > 0)
        for pub in inp.taproot_bip32_derivations:
            leaf_hashes, der = inp.taproot_bip32_derivations[pub]
            self.assertTrue(der.fingerprint is not None)
            self.assertTrue(der.derivation is not None)

    def test_serialize_deserialize(self):
        """Tests that PSBT with taproot derivations serialized without losing any data"""
        for b64 in TAP_PSBTS:
            psbt = PSBT.from_string(b64)
            ser = psbt.to_string()
            self.assertEqual(len(ser), len(b64))
            psbt2 = PSBT.from_string(ser)
            assert psbt == psbt2

    def test_sign_internal(self):
        """Test we can sign with internal key"""
        for b64psbt, sigs in zip(TAP_PSBTS, TAP_SIGS):
            psbt = PSBT.from_string(b64psbt)
            psbt.sign_with(KEY_A)
            self.assertEqual(psbt.inputs[0].final_scriptwitness.items[0], sigs[0])

    def test_sign_taptree(self):
        """Test we can sign with internal key"""
        psbt = PSBT.from_string(TAPTREE_PSBT)
        for key in TAPTREE_KEYS:
            psbt.sign_with(key)
        # check internal key signature
        self.assertEqual(psbt.inputs[0].final_scriptwitness.items[0], TAPTREE_SIGS[0])
        # check taptree signatures
        for sig in TAPTREE_SIGS[1:]:
            self.assertTrue(sig in psbt.inputs[0].taproot_sigs.values())

    def test_owns(self):
        d = Descriptor.from_string("tr(%s/86h/1h/0h/{0,1}/*)" % KEY_A)
        psbt = PSBT.from_string(TAP_PSBTS[0])
        # in this PSBT whenever we have derivations it is owned by the descriptor
        for sc in psbt.inputs + psbt.outputs:
            self.assertEqual(d.owns(sc), bool(sc.taproot_bip32_derivations))

    def test_sign_psbtview(self):
        psbt = PSBT.from_string(TAP_PSBTS[0])
        b = BytesIO(psbt.serialize())
        psbtv = PSBTView.view(b)
        # sign into signature stream
        sigs_stream = BytesIO()
        psbt.sign_with(KEY_A)
        psbtv.sign_with(KEY_A, sigs_stream)
        sigs_stream.seek(0,0)
        # serialize psbtview into bytestream and parse back into psbt - for convenient
        ser = BytesIO()
        psbtv.write_to(ser, extra_input_streams=[sigs_stream])
        ser.seek(0,0)
        psbt2 = PSBT.read_from(ser)
        # check signatures in every input
        for inp1, inp2 in zip(psbt.inputs, psbt2.inputs):
            self.assertTrue(bool(inp1.final_scriptwitness)) # test not empty
            self.assertEqual(inp1.final_scriptwitness, inp2.final_scriptwitness) # test psbt and psbtview give the same results
