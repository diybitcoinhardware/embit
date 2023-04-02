from unittest import TestCase
from embit.descriptor import Descriptor
from embit.networks import NETWORKS

NETWORK = NETWORKS['test']

TPRVS = [
    "tprv8ZgxMBicQKsPerQj6m35no46amfKQdjY7AhLnmatHYXs8S4MTgeZYkWAn4edSGwwL3vkSiiGqSZQrmy5D3P5gBoqgvYP2fCUpBwbKTMTAkL",
    "tprv8ZgxMBicQKsPd3cbrKjE5GKKJLDEidhtzSSmPVtSPyoHQGL2LZw49yt9foZsN9BeiC5VqRaESUSDV2PS9w7zAVBSK6EQH3CZW9sMKxSKDwD",
    "tprv8iF7W37EHnVEtDr9EFeyFjQJFL6SfGby2AnZ2vQARxTQHQXy9tdzZvBBVp8a19e5vXhskczLkJ1AZjqgScqWL4FpmXVp8LLjiorcrFK63Sr",
]
TPUBS = [
    "tpubD6NzVbkrYhZ4YPAbyf6urxqqnmJF79PzQtyERAmvkSVS9fweCTjxjDh22Z5St9fGb1a5DUCv8G27nYupKP1Ctr1pkamJossoetzws1moNRn",
    "tpubD6NzVbkrYhZ4YMQC15JS7QcrsAyfGrGiykweqMmPxTkEVScu7vCZLNpPXW1XphHwzsgmqdHWDQAfucbM72EEB1ZEyfgZxYvkZjYVXx1xS9p",
    "tpubD6NzVbkrYhZ4YU9vM1s53UhD75UyJatx8EMzMZ3VUjR2FciNfLLkAw6a4pWACChzobTseNqdWk4G7ZdBqRDLtLSACKykTScmqibb1ZrCvJu",
    "tpubD6NzVbkrYhZ4XRMcMFMMFvzVt6jaDAtjZhD7JLwdPdMm9xa76DnxYYP7w9TZGJDVFkek3ArwVsuacheqqPog8TH5iBCX1wuig8PLXim4n9a",
    "tpubD6NzVbkrYhZ4WsqRzDmkL82SWcu42JzUvKWzrJHQ8EC2vEHRHkXj1De93sD3biLrKd8XGnamXURGjMbYavbszVDXpjXV2cGUERucLJkE6cy",
    "tpubDEFLeBkKTm8aiYkySz8hXAXPVnPSfxMi7Fxhg9sejUrkwJuRWvPdLEiXjTDbhGbjLKCZUDUUibLxTnK5UP1q7qYrSnPqnNe7M8mvAW1STcc",
    "tpubD6NzVbkrYhZ4WR99ygpiJvPMAJiwahjLgGywc5vJx2gUfKUfEPCrbKmQczDPJZmLcyZzRb5Ti6rfUb89S2WFyPH7FDtD6RFDA1hdgTEgEUL",
]
PUBKEYS = [
    "02aebf2d10b040eb936a6f02f44ee82f8b34f5c1ccb20ff3949c2b28206b7c1068",
    "030f64b922aee2fd597f104bc6cb3b670f1ca2c6c49b1071a1a6c010575d94fe5a",
    "02abe475b199ec3d62fa576faee16a334fdb86ffb26dce75becebaaedf328ac3fe",
    "0314f3dc33595b0d016bb522f6fe3a67680723d842c1b9b8ae6b59fdd8ab5cccb4",
    "025eba3305bd3c829e4e1551aac7358e4178832c739e4fc4729effe428de0398ab",
    "029ffbe722b147f3035c87cb1c60b9a5947dd49c774cc31e94773478711a929ac0",
    "0211c7b2e18b6fd330f322de087da62da92ae2ae3d0b7cec7e616479cce175f183",
]

P2WSH_MINISCRIPTS = [
    # One of two keys
    "or_b(pk(%s/*),s:pk(%s/*))" % (TPUBS[0], TPUBS[1]),
    # A script similar (same spending policy) to BOLT3's offered HTLC (with anchor outputs)
    "or_d(pk(%s/*),and_v(and_v(v:pk(%s/*),or_c(pk(%s/*),v:hash160(7f999c905d5e35cefd0a37673f746eb13fba3640))),older(1)))" % (TPUBS[0], TPUBS[1], TPUBS[2]),
    # A Revault Unvault policy with the older() replaced by an after()
    "andor(multi(2,%s/*,%s/*),and_v(v:multi(4,%s,%s,%s,%s),after(424242)),thresh(4,pkh(%s/*),a:pkh(%s/*),a:pkh(%s/*),a:pkh(%s/*)))" % (TPUBS[0], TPUBS[1], PUBKEYS[0], PUBKEYS[1], PUBKEYS[2], PUBKEYS[3], TPUBS[2], TPUBS[3], TPUBS[4], TPUBS[5]),
    # Liquid-like federated pegin with emergency recovery keys
    "or_i(and_b(pk(%s),a:and_b(pk(%s),a:and_b(pk(%s),a:and_b(pk(%s),s:pk(%s))))),and_v(v:thresh(2,pkh(%s/*),a:pkh(%s),a:pkh(%s)),older(4209713)))" % (PUBKEYS[0], PUBKEYS[1], PUBKEYS[2], PUBKEYS[3], PUBKEYS[4], TPUBS[0], PUBKEYS[5], PUBKEYS[6]),
]

DESCS = ["wsh(%s)" % ms for ms in P2WSH_MINISCRIPTS] + [
    # one pubkey in taptree
    "tr(4d54bb9928a0683b7e383de72943b214b0716f58aa54c7ba6bcea2328bc9c768,pk(%s))" % PUBKEYS[0],
    # A Taproot with one of the above scripts as the single script path.
    "tr(4d54bb9928a0683b7e383de72943b214b0716f58aa54c7ba6bcea2328bc9c768,%s)" % P2WSH_MINISCRIPTS[0],
    # A Taproot with two script paths among the above scripts.
    "tr(4d54bb9928a0683b7e383de72943b214b0716f58aa54c7ba6bcea2328bc9c768,{%s,%s})" % (P2WSH_MINISCRIPTS[0], P2WSH_MINISCRIPTS[1]),
    # A Taproot with three script paths among the above scripts.
    "tr(4d54bb9928a0683b7e383de72943b214b0716f58aa54c7ba6bcea2328bc9c768,{{%s,%s},%s})" % (P2WSH_MINISCRIPTS[0], P2WSH_MINISCRIPTS[1], P2WSH_MINISCRIPTS[2].replace("multi", "multi_a")),
    # A Taproot with all above scripts in its tree.
    "tr(4d54bb9928a0683b7e383de72943b214b0716f58aa54c7ba6bcea2328bc9c768,{{%s,%s},{%s,%s}})"% (P2WSH_MINISCRIPTS[0], P2WSH_MINISCRIPTS[1], P2WSH_MINISCRIPTS[2].replace("multi", "multi_a"), P2WSH_MINISCRIPTS[3]),
]

# expected addresses for all descriptors with derivation index 0
ADDRESSES = [
    "tb1qfxrnzaaa2f3na8tsv7up4ntm87ypdvmhmgyvf9glceft08zxquds4e4nkh",
    "tb1q7j0nx23h9gpgm2gf9zzkg9dg49jrqq0f9lhnzxtxzf3wwqe9943svq9s03",
    "tb1qr9yt77ej508pj723egt2sprxz32r7pvs5glg0jg32xxl83sfm3sqwlttzn",
    "tb1qrgwwjs3n69znlq9z254fmx28hyamhwqjcuu5vfnyklvje5v4rjdqxzefdr",
    None, #"tb1p0k3h2ce3t5r40whug6q8scjlgh2naza2yw2w9gtstr76ct02cffqq2yvst",
    None, #"tb1pesu98mtyfdjg00fs3hs3gfq5l3vj0fsezm27e5dcgfux7w7hxhssy6xgft",
    None, #"tb1pjtyykgnzx4yspt06kwqx6vausjf07puezuhryuhypw243484tj3qy2thxw",
    None, #"tb1pezhhsmppds98a5mjskgwwmucynnq0307lf4l9cwmjxhsnx070nxqc5xnn7",
    None, #"tb1plueckktz4n872cqk5nskscm2n9f68xtnfuec08ra59knur5dw6kshc3xf9",
]

# TODO: test that:
# - xonly pubkey can be only used in taproot descriptors
# - sec pubkeys or xpubs can be used in taproot as root key
# - p2tr accepts empty pubkey if taptree is set
# - multi and sortedmulti can't be used in taproot
# - multi_a can't be used outside of taproot

class TapTreeTest(TestCase):
    def test_addresses(self):
        for d, addr in zip(DESCS, ADDRESSES):
            if addr is not None:
                self.assertEqual(Descriptor.from_string(d).derive(0).address(NETWORK), addr)

