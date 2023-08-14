from unittest import TestCase
from binascii import hexlify
from embit.descriptor import Descriptor, Key
from embit.descriptor.arguments import KeyHash, Number
from embit.descriptor.miniscript import OPERATORS, WRAPPERS, Miniscript
from embit.descriptor.checksum import add_checksum, DescriptorError
from embit import ec


class DescriptorTest(TestCase):
    def test_desc_checksum(self):
        """Tests descriptor checksums"""
        desc = (
            "wpkh([c1684a69/84'/1'/0']tpubDDY2HTrz5YTJGe4dejjxgiiuex6Gfu7Ca21z"
            "EkCf7GcWpPhpM172yt9aeJqWg5zD7n6gUFfnFJeyMokc54rCQ9tWLjs9VaZHxV95g"
            "6RYjf5/1/*)#2zrpegx5"
        )
        self.assertEqual(add_checksum(desc.split("#")[0]), desc)
        self.assertRaises(DescriptorError, add_checksum, " ✘")

    def test_descriptors(self):
        keys = [
            "[abcdef12/84h/22h]xpub6F6wWxm8F64iBHNhyaoh3QKCuuMUY5pfPPr1H1WuZXUXeXtZ21qjFN5ykaqnLL1jtPEFB9d94CyZrcYWKVdSiJKQ6mLGEB5sfrGFBpg6wgA/<0;1>/*",
            "03e7d285b4817f83f724cd29394da75dfc84fe639ed147a944e7e6064703b14130",
            "[12345678/44h/12]xpub6BwcvdstHTJtLpp1WxUiQCYERWSB66XY5JrCpw71GAJxcJ6s2AiUoEK4Nzt6UDaTmanUiSe6TY2RoFturKNLXeWBhwBF6WBNghr8cr7qnjk/<0;1>/*",
            "[12345a78/42h/15]03e7d285b4817f83f724cd29394da75dfc84fe639ed147a944e7e6064703b14130",
        ]

        dd = [
            (
                "wsh(or_d("
                "c:pk_k(020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261),"
                "c:pk_k(0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352)"
                "))",
                "21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261ac7364210250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352ac68",
            ),
            # # pkh - 8e5d7457d33a978d1c3c1e440f92a195e00cc7d8
            # ("wsh(v:pk_h(03e7d285b4817f83f724cd29394da75dfc84fe639ed147a944e7e6064703b14130))", None),
            (
                "sh(wsh(and_v(or_c(pk(%s),or_c(pk(%s),v:older(1000))),pk(%s))))"
                % tuple(keys[-3:]),
                "2103e7d285b4817f83f724cd29394da75dfc84fe639ed147a944e7e6064703b14130ac642103b8fa5d5959fa4027ccbf0736a86ccde4242e3051ea363437b4ff0d52598d7cecac6402e803b26968682103e7d285b4817f83f724cd29394da75dfc84fe639ed147a944e7e6064703b14130ac",
            ),
            (
                "sh(or_b(pk(%s),s:pk(%s)))" % tuple(keys[:2]),
                "2103801b3a4e3ca0d61d469445621561c47f6c1424d0fd353a44c2c3ebb84ae78f59ac7c2103e7d285b4817f83f724cd29394da75dfc84fe639ed147a944e7e6064703b14130ac9b",
            ),
            (
                "wsh(or_d(pk(%s),pkh(%s)))" % tuple(keys[-2:]),
                "2103b8fa5d5959fa4027ccbf0736a86ccde4242e3051ea363437b4ff0d52598d7cecac736476a9148e5d7457d33a978d1c3c1e440f92a195e00cc7d888ac68",
            ),
            (
                "wsh(and_v(v:pk(%s),or_d(pk(%s),older(12960))))" % tuple(keys[:2]),
                "2103801b3a4e3ca0d61d469445621561c47f6c1424d0fd353a44c2c3ebb84ae78f59ad2103e7d285b4817f83f724cd29394da75dfc84fe639ed147a944e7e6064703b14130ac736402a032b268",
            ),
            (
                "wsh(andor(pk(%s),older(1008),pk(%s)))" % tuple(keys[:2]),
                "2103801b3a4e3ca0d61d469445621561c47f6c1424d0fd353a44c2c3ebb84ae78f59ac642103e7d285b4817f83f724cd29394da75dfc84fe639ed147a944e7e6064703b14130ac6702f003b268",
            ),
            (
                "wsh(t:or_c(pk(%s),and_v(v:pk(%s),or_c(pk(%s),v:hash160(e7d285b4817f83f724cd29394da75dfc84fe639e)))))"
                % tuple(keys[:3]),
                "2103801b3a4e3ca0d61d469445621561c47f6c1424d0fd353a44c2c3ebb84ae78f59ac642103e7d285b4817f83f724cd29394da75dfc84fe639ed147a944e7e6064703b14130ad2103b8fa5d5959fa4027ccbf0736a86ccde4242e3051ea363437b4ff0d52598d7cecac6482012088a914e7d285b4817f83f724cd29394da75dfc84fe639e88686851",
            ),
            (
                "wsh(andor(pk(%s),or_i(and_v(v:pkh(%s),hash160(e7d285b4817f83f724cd29394da75dfc84fe639e)),older(1008)),pk(%s)))"
                % tuple(keys[:3]),
                "2103801b3a4e3ca0d61d469445621561c47f6c1424d0fd353a44c2c3ebb84ae78f59ac642103b8fa5d5959fa4027ccbf0736a86ccde4242e3051ea363437b4ff0d52598d7cecac676376a9148e5d7457d33a978d1c3c1e440f92a195e00cc7d888ad82012088a914e7d285b4817f83f724cd29394da75dfc84fe639e876702f003b26868",
            ),
            (
                "wsh(multi(2,%s,%s,%s))" % tuple(keys[:3]),
                "522103801b3a4e3ca0d61d469445621561c47f6c1424d0fd353a44c2c3ebb84ae78f592103e7d285b4817f83f724cd29394da75dfc84fe639ed147a944e7e6064703b141302103b8fa5d5959fa4027ccbf0736a86ccde4242e3051ea363437b4ff0d52598d7cec53ae",
            ),
            # TODO: invalid miniscript for segwit, but valid for taproot
            # ("wsh(thresh(3,pk(%s),s:pk(%s),s:pk(%s),sdv:older(12960)))" % tuple(keys[:3]),
            #  "2103801b3a4e3ca0d61d469445621561c47f6c1424d0fd353a44c2c3ebb84ae78f59ac7c2103e7d285b4817f83f724cd29394da75dfc84fe639ed147a944e7e6064703b14130ac937c2103b8fa5d5959fa4027ccbf0736a86ccde4242e3051ea363437b4ff0d52598d7cecac937c766302a032b26968935387"),
            (
                "wsh(multi(10,"
                "0373b665b6fe153c5872de1344339ee60588491257d2c34567aa026af237143a6c,"
                "02916ee61974fc4892afb2d3cad4c13472138b5521411de24a78910afb97b95f22,"
                "0244efc096ea3b7df99071b1cfa1630144e20d8ccd1540e726034a051aa1802d3b,"
                "02d9c51dc3f4088d5ce0b83f188fb14901b98c1c9e8cf771c49b7b441e56272b8a,"
                "03094990a34af21ef3ed766c8e0cb1e44f5e0d80412bbe00a2ade82a024ca91d23,"
                "02722a386ad0f6d7f1261808a3e70fab143303bd2264283486411c3183ea3ed1c3,"
                "036070b1f2995d8ffda8478ef55affd39795689a3982d54b12180397b1ad1f5f75,"
                "026515fa7603c10c44f6d316ae7592b5899d46d87ac1e574ec53de8b59f95efad6,"
                "038c8f919f70062c084376223fd8b4f0c08958e70499df496411dde83a1bb64b0d,"
                "02d0ea7084e344b56625277b074d15a15301b9d96b0b2dd9fc905e01fc3de408e1))",
                "5a210373b665b6fe153c5872de1344339ee60588491257d2c34567aa026af237143a6c2102916ee61974fc4892afb2d3cad4c13472138b5521411de24a78910afb97b95f22210244efc096ea3b7df99071b1cfa1630144e20d8ccd1540e726034a051aa1802d3b2102d9c51dc3f4088d5ce0b83f188fb14901b98c1c9e8cf771c49b7b441e56272b8a2103094990a34af21ef3ed766c8e0cb1e44f5e0d80412bbe00a2ade82a024ca91d232102722a386ad0f6d7f1261808a3e70fab143303bd2264283486411c3183ea3ed1c321036070b1f2995d8ffda8478ef55affd39795689a3982d54b12180397b1ad1f5f7521026515fa7603c10c44f6d316ae7592b5899d46d87ac1e574ec53de8b59f95efad621038c8f919f70062c084376223fd8b4f0c08958e70499df496411dde83a1bb64b0d2102d0ea7084e344b56625277b074d15a15301b9d96b0b2dd9fc905e01fc3de408e15aae",
            ),
            (
                "wsh(andor("
                "multi(4,"
                "036070b1f2995d8ffda8478ef55affd39795689a3982d54b12180397b1ad1f5f75,"
                "026515fa7603c10c44f6d316ae7592b5899d46d87ac1e574ec53de8b59f95efad6,"
                "038c8f919f70062c084376223fd8b4f0c08958e70499df496411dde83a1bb64b0d,"
                "02d0ea7084e344b56625277b074d15a15301b9d96b0b2dd9fc905e01fc3de408e1),"
                "and_v("
                "v:multi(6,"
                "03856d447f1b890cc6e0e0114cd5bac58662c37ce7f458c458b72bd396597edfc7,"
                "03e080e99896384aa8a07da837b2042a4c0d824eeaa8d51e6c9cff20682be75d4f,"
                "02c6d258e728005d4d00e55ac4b87786df507921b3ba3efec244a47f4a2e61b4b0,"
                "02edfc1d6088f9b6470ed4550d8bf2326ebebc0464a7f78581fa7283fc54edecf0,"
                "02f3630d1f51b2ebaaf1c7ebae9c24318279d4cff5ad16cb290b6d26edf96dca9c,"
                "0353ecc8e7b1cc90d405cd6fc9d9f24d44b6b5649abc2773f28a6ca4fa7a4cd629),"
                "older(144)),"
                "thresh(5,"
                "pkh(1ad3ca2d247b8e8888e41f89ac8bef217d83f33f),"
                "a:pkh(f94f2eadc9c1bc3a8b8c2c6364af2c070fd41206),"
                "a:pkh(3c306c2c97e4ba62ac0d7fb3965aba66b28e8959),"
                "a:pkh(ba7b9e846eb6b16420976c6bead54d9bb2b08d35),"
                "a:pkh(379ed952eb4740386acc59c2d28d9aa62e63968d),"
                "a:pkh(c30d2795e70b1ee6f8af0b33d9460d60cfcf10b3))))",
                "5421036070b1f2995d8ffda8478ef55affd39795689a3982d54b12180397b1ad1f5f7521026515fa7603c10c44f6d316ae7592b5899d46d87ac1e574ec53de8b59f95efad621038c8f919f70062c084376223fd8b4f0c08958e70499df496411dde83a1bb64b0d2102d0ea7084e344b56625277b074d15a15301b9d96b0b2dd9fc905e01fc3de408e154ae6476a9141ad3ca2d247b8e8888e41f89ac8bef217d83f33f88ac6b76a914f94f2eadc9c1bc3a8b8c2c6364af2c070fd4120688ac6c936b76a9143c306c2c97e4ba62ac0d7fb3965aba66b28e895988ac6c936b76a914ba7b9e846eb6b16420976c6bead54d9bb2b08d3588ac6c936b76a914379ed952eb4740386acc59c2d28d9aa62e63968d88ac6c936b76a914c30d2795e70b1ee6f8af0b33d9460d60cfcf10b388ac6c93558767562103856d447f1b890cc6e0e0114cd5bac58662c37ce7f458c458b72bd396597edfc72103e080e99896384aa8a07da837b2042a4c0d824eeaa8d51e6c9cff20682be75d4f2102c6d258e728005d4d00e55ac4b87786df507921b3ba3efec244a47f4a2e61b4b02102edfc1d6088f9b6470ed4550d8bf2326ebebc0464a7f78581fa7283fc54edecf02102f3630d1f51b2ebaaf1c7ebae9c24318279d4cff5ad16cb290b6d26edf96dca9c210353ecc8e7b1cc90d405cd6fc9d9f24d44b6b5649abc2773f28a6ca4fa7a4cd62956af029000b268",
            ),
            (
                "wsh(sortedmulti(2,%s,%s,%s))" % tuple(keys[:3]),
                "522103801b3a4e3ca0d61d469445621561c47f6c1424d0fd353a44c2c3ebb84ae78f592103b8fa5d5959fa4027ccbf0736a86ccde4242e3051ea363437b4ff0d52598d7cec2103e7d285b4817f83f724cd29394da75dfc84fe639ed147a944e7e6064703b1413053ae",
            ),
            ("wpkh(%s)" % keys[0], "0014f8f93df2160de8fd3ca716e2f905c74da3f9839f"),
            ("sh(wpkh(%s))" % keys[0], "0014f8f93df2160de8fd3ca716e2f905c74da3f9839f"),
            ("pkh(%s)" % keys[0], "76a914f8f93df2160de8fd3ca716e2f905c74da3f9839f88ac"),
        ]

        for i, (d, a) in enumerate(dd):
            sc = Descriptor.from_string(d)
            self.assertEqual(str(sc), d)
            # get top level script
            scc = sc.witness_script() or sc.redeem_script() or sc.script_pubkey()
            self.assertEqual(len(scc.data), sc.script_len)
            schex = hexlify(scc.data).decode()
            self.assertEqual(schex, a)
            self.assertEqual(str(sc), d)

    def test_keys(self):
        keys = [
            "[f45912ab/44h/12/32h]xpub6F6wWxm8F64iBHNhyaoh3QKCuuMUY5pfPPr1H1WuZXUXeXtZ21qjFN5ykaqnLL1jtPEFB9d94CyZrcYWKVdSiJKQ6mLGEB5sfrGFBpg6wgA",
            "[f45912ab/44h/12/32h]02edfc1d6088f9b6470ed4550d8bf2326ebebc0464a7f78581fa7283fc54edecf0",
            "02edfc1d6088f9b6470ed4550d8bf2326ebebc0464a7f78581fa7283fc54edecf0",
            "[f45912ab/44h/12/32h]xpub6F6wWxm8F64iBHNhyaoh3QKCuuMUY5pfPPr1H1WuZXUXeXtZ21qjFN5ykaqnLL1jtPEFB9d94CyZrcYWKVdSiJKQ6mLGEB5sfrGFBpg6wgA/0/*",
            "[f45912ab/44h/12/32h]xprvA1BtcqnJTKdjRQJ4K2874WTDyPCvgT7bCte7cXi4XrZ5csfoVqgWAL61U9dSf3xE9GUDrFL6RnxPRGvHMn85MHbuKSHDp4vqmJ7PK1Eewug/<0;1>/*",
            "[f45912ab/44h/12/32h]xpub6F6wWxm8F64iBHNhyaoh3QKCuuMUY5pfPPr1H1WuZXUXeXtZ21qjFN5ykaqnLL1jtPEFB9d94CyZrcYWKVdSiJKQ6mLGEB5sfrGFBpg6wgA/0/56/*/<1;5>/54",
            "KwF4aJaqLFBUyGpJqWWGBPJkDSXnEVwheaFNz5UEWqFPd43exAMB",
            "[f45912ab/44h/12/32h]KwF4aJaqLFBUyGpJqWWGBPJkDSXnEVwheaFNz5UEWqFPd43exAMB",
            "[f45912ab/44h/12/32h]xprvA1BtcqnJTKdjRQJ4K2874WTDyPCvgT7bCte7cXi4XrZ5csfoVqgWAL61U9dSf3xE9GUDrFL6RnxPRGvHMn85MHbuKSHDp4vqmJ7PK1Eewug/<0h;1>/34h/*",
            # keyhash
            "a2edfc1d6088f9b6470ed4550d8bf2326ebebc04",
            "[f45912ab/44h/12/32h]a2edfc1d6088f9b6470ed4550d8bf2326ebebc04",
        ]
        for k in keys:
            kk = KeyHash.from_string(k)
            self.assertEqual(str(kk), k)
            if kk.can_derive:
                kkk = kk.derive(88)
                self.assertFalse(kkk.can_derive)

    def test_branch_compatibility(self):
        keys = [
            "[f45912ab/44h/12/32h]xpub6F6wWxm8F64iBHNhyaoh3QKCuuMUY5pfPPr1H1WuZXUXeXtZ21qjFN5ykaqnLL1jtPEFB9d94CyZrcYWKVdSiJKQ6mLGEB5sfrGFBpg6wgA/<0>/*",
            "[f45912ab/44h/12/32h]xprvA1BtcqnJTKdjRQJ4K2874WTDyPCvgT7bCte7cXi4XrZ5csfoVqgWAL61U9dSf3xE9GUDrFL6RnxPRGvHMn85MHbuKSHDp4vqmJ7PK1Eewug/<0;1>/*",
            "[f45912ab/44h/12/32h]xpub6F6wWxm8F64iBHNhyaoh3QKCuuMUY5pfPPr1H1WuZXUXeXtZ21qjFN5ykaqnLL1jtPEFB9d94CyZrcYWKVdSiJKQ6mLGEB5sfrGFBpg6wgA/0/56/*/<1;5>/54",
            "[f45912ab/44h/12/32h]xprvA1BtcqnJTKdjRQJ4K2874WTDyPCvgT7bCte7cXi4XrZ5csfoVqgWAL61U9dSf3xE9GUDrFL6RnxPRGvHMn85MHbuKSHDp4vqmJ7PK1Eewug/<0h;1>/34h/*",
        ]
        for k in keys:
            kk = Key.from_string(
                k.replace("<", "{").replace(">", "}").replace(";", ",")
            )
            self.assertEqual(str(kk), k)
            if kk.can_derive:
                kkk = kk.derive(88)
                self.assertFalse(kkk.can_derive)

    def test_branch_mixing(self):
        keys = [
            "[f45912ab/44h/12/32h]xpub6F6wWxm8F64iBHNhyaoh3QKCuuMUY5pfPPr1H1WuZXUXeXtZ21qjFN5ykaqnLL1jtPEFB9d94CyZrcYWKVdSiJKQ6mLGEB5sfrGFBpg6wgA/<0}/*",
            "[f45912ab/44h/12/32h]xprvA1BtcqnJTKdjRQJ4K2874WTDyPCvgT7bCte7cXi4XrZ5csfoVqgWAL61U9dSf3xE9GUDrFL6RnxPRGvHMn85MHbuKSHDp4vqmJ7PK1Eewug/{0;1}/*",
            "[f45912ab/44h/12/32h]xpub6F6wWxm8F64iBHNhyaoh3QKCuuMUY5pfPPr1H1WuZXUXeXtZ21qjFN5ykaqnLL1jtPEFB9d94CyZrcYWKVdSiJKQ6mLGEB5sfrGFBpg6wgA/0/56/*/<1,5>/54",
            "[f45912ab/44h/12/32h]xprvA1BtcqnJTKdjRQJ4K2874WTDyPCvgT7bCte7cXi4XrZ5csfoVqgWAL61U9dSf3xE9GUDrFL6RnxPRGvHMn85MHbuKSHDp4vqmJ7PK1Eewug/<*;1>/34h/*",
        ]
        for k in keys:
            try:
                Key.from_string(k)
                print(k)
            except:
                pass
            self.assertRaises(Exception, Key.from_string, k)

    def test_miniscript_compat(self):
        """Test we can parse Miniscript Descriptors created by other implementations"""
        generalistic_descs = [
            "wsh(thresh(1,pk(xpub6BaZSKgpaVvibu2k78QsqeDWXp92xLHZxiu1WoqLB9hKhsBf3miBUDX7PJLgSPvkj66ThVHTqdnbXpeu8crXFmDUd4HeM4s4miQS2xsv3Qb/*)))#cwycq5x",
            "wsh(multi(2,xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU/*,xpub6AaffFGfH6WXfm6pwWzmUMuECQnoLeB3agMKaLyEBZ5ZVfwtnS5VJKqXBt8o5ooCWVy2H87GsZshp7DeKE25eWLyd1Ccuh2ZubQUkgpiVux/*))#n3cj9mhy",
            "wsh(andor(thresh(1,pk(xpub6BaZSKgpaVvibu2k78QsqeDWXp92xLHZxiu1WoqLB9hKhsBf3miBUDX7PJLgSPvkj66ThVHTqdnbXpeu8crXFmDUd4HeM4s4miQS2xsv3Qb/*)),and_v(v:multi(2,03b506a1dbe57b4bf48c95e0c7d417b87dd3b4349d290d2e7e9ba72c912652d80a,0295e7f5d12a2061f1fd2286cefec592dff656a19f55f4f01305d6aa56630880ce),older(6)),thresh(2,pkh(xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU/*),a:pkh(xpub6AaffFGfH6WXfm6pwWzmUMuECQnoLeB3agMKaLyEBZ5ZVfwtnS5VJKqXBt8o5ooCWVy2H87GsZshp7DeKE25eWLyd1Ccuh2ZubQUkgpiVux/*))))#76jsyzdg",
            "wsh(or_d(pk([40259ab7/48'/1'/0'/2']tpubDFcY6nTiMAWBd5d2bS8JZvjcaLjC6GE6XnPAJAPUkVj5wa5Pyb4gumx1ZWvnXQ8tmorCmpAyai69K9hD2mGQUeNkuXfjztsfqnE5FMk1CCh/<0;1>/*),and_v(v:pkh([842a626e/48'/1'/0'/2']tpubDENBboujRvpkS8SgZsrpqG2BCUBoaAc4c57jHFe1NwKAtfVjDZDUadQKYv4pkAEF2afPv6TtQ2BoYFJAPLbuKpL1usiySERZekGo4JmnWhh/<0;1>/*),older(65535))))#deguz53x",
            "wsh(or_d(pk([40259ab7/48h/1h/0h/2h]tpubDFcY6nTiMAWBd5d2bS8JZvjcaLjC6GE6XnPAJAPUkVj5wa5Pyb4gumx1ZWvnXQ8tmorCmpAyai69K9hD2mGQUeNkuXfjztsfqnE5FMk1CCh/<0;1>/*),and_v(v:pkh([842a626e/48H/1H/0H/2H]tpubDENBboujRvpkS8SgZsrpqG2BCUBoaAc4c57jHFe1NwKAtfVjDZDUadQKYv4pkAEF2afPv6TtQ2BoYFJAPLbuKpL1usiySERZekGo4JmnWhh/<0;1>/*),older(65535))))#deguz53x",
        ]

        for desc in generalistic_descs:
            Descriptor.from_string(desc)

    def test_len(self):
        """Checks that len(miniscript) returns correct length"""
        for op in OPERATORS:
            nargs = op.NARGS
            if nargs is None:
                nargs = 3
            o = op(*[Number(55) for i in range(nargs)])
            self.assertEqual(len(o), len(o.compile()))
        for wr in WRAPPERS:
            w = wr(o)
            self.assertEqual(len(w), len(w.compile()))

    def test_multisig(self):
        keys = tuple([ec.PrivateKey(bytes([i + 1] * 32)).to_public() for i in range(4)])
        miniscripts = [
            # descriptor: str, is_basic_multisig: bool, is_sorted: bool
            (
                "c:andor(multi(1,%s,%s),pk_k(%s),pk_k(%s))" % keys,
                False,
                False,
            ),
            (
                "multi(2,%s,%s,%s,%s)" % keys,
                True,
                False,
            ),
            (
                "multi_a(2,%s,%s,%s,%s)" % keys,
                True,
                False,
            ),
            (
                "sortedmulti(2,%s,%s,%s,%s)" % keys,
                True,
                True,
            ),
            (
                "sortedmulti_a(2,%s,%s,%s,%s)" % keys,
                True,
                True,
            ),
        ]
        for m, is_basic, is_sorted in miniscripts:
            d = Descriptor.from_string("wsh(%s)" % m)
            self.assertEqual(d.is_basic_multisig, is_basic)
            self.assertEqual(d.is_sorted, is_sorted)


# test that:
# + str(d) == d
# + compile() works correctly
# - derived key works with:
#   - [mfp/der]xpub
#   - wif
#   - xprv
#   - xpub/fixed
#   - xpub/<allowed_set>/*
#   - xpub/123/0/*/4
#   - xpub/{receive:0,change:1,revault:2,whatever:4}/*
#   - xpub/0/* should make it recv-only
