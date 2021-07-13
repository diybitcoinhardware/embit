from unittest import TestCase
from embit.bip32 import HDKey
from embit.networks import NETWORKS
from embit.script import p2tr, address_to_scriptpubkey
from embit.descriptor import Descriptor

KEY = "tprv8ZgxMBicQKsPf27gmh4DbQqN2K6xnXA7m7AeceqQVGkRYny3X49sgcufzbJcq4k5eaGZDMijccdDzvQga2Saqd78dKqN52QwLyqgY8apX3j"
ROOT = HDKey.from_string(KEY)
NET = NETWORKS["regtest"]

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
            pub = ROOT.derive([0, i])
            sc = p2tr(pub)
            self.assertEqual(sc.address(NET), addr)
            self.assertEqual(address_to_scriptpubkey(addr), sc)

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
