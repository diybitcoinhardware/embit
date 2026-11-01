from binascii import hexlify, unhexlify
from io import BytesIO
from unittest import TestCase

from embit import compact, hashes
from embit.psbt import PSBTError
from embit.psbtview import PSBTView
from embit.script import Script
from embit.transaction import Transaction, TransactionError

# keyPathSpending of BIP-341's wallet-test-vectors.json
RAW_TX = (
    "02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b5596311"
    "5f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6de"
    "f61273e127517d44759b6dafdd990000000000fffffffff8e1f5833843336892"
    "28c5d28eac13366be082dc57441760d957275419a418420000000000ffffffff"
    "f0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b"
    "0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd"
    "3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa"
    "29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b"
    "88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c940100000000"
    "00000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7ea"
    "dfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a9966772"
    "0b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b0000000019"
    "76a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb000000"
    "0020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab"
    "962b0065cd1d"
)
# (amount, scriptPubKey) of each spent output
UTXOS = [
    (420000000, "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"),
    (462000000, "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3"),
    (294000000, "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"),
    (504000000, "5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e"),
    (630000000, "512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605"),
    (378000000, "00147dd65592d0ab2fe0d0257d571abf032cd9db93dc"),
    (672000000, "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831"),
    (546000000, "5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5"),
    (588000000, "512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220"),
]
# (input index, hash type, sigHash)
SIGHASHES = [
    (
        0,
        0x03,
        "2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555",
    ),
    (
        1,
        0x83,
        "325a644af47e8a5a2591cda0ab0723978537318f10e6a63d4eed783b96a71a4d",
    ),
    (
        3,
        0x01,
        "bf013ea93474aa67815b1b6cc441d23b64fa310911d991e713cd34c7f5d46669",
    ),
    (
        4,
        0x00,
        "4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef",
    ),
    (
        6,
        0x02,
        "15f25c298eb5cdc7eb1d638dd2d45c97c4c59dcaec6679cfc16ad84f30876b85",
    ),
    (
        7,
        0x82,
        "cd292de50313804dabe4685e83f923d2969577191a3e1d2882220dca88cbeb10",
    ),
    (
        8,
        0x81,
        "cccb739eca6c13a8a89e6e5cd317ffe55669bbda23f2fd37b0f18755e008edd2",
    ),
]
# (input index, hash type, sigMsg) of the vectors with SIGHASH_SINGLE
SINGLE_SIGMSGS = [
    (
        0,
        0x03,
        "0003020000000065cd1de3b33bb4ef3a52ad1fffb555c0d82828eb22737036eaeb02"
        "a235d82b909c4c3f58a6964a4f5f8f0b642ded0a8a553be7622a719da71d1f5befce"
        "fcdee8e0fde623ad0f61ad2bca5ba6a7693f50fce988e17c3780bf2b1e720cfbb38f"
        "bdd52e2118959c7221ab5ce9e26c3cd67b22c24f8baa54bac281d8e6b05e400e6c3a"
        "957e0000000000d0418f0e9a36245b9a50ec87f8bf5be5bcae434337b87139c3a5b1"
        "f56e33cba0",
    ),
    (
        1,
        0x83,
        "0083020000000065cd1d00d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127"
        "517d44759b6dafdd9900000000808f891b00000000225120147c9c57132f6e7ecddb"
        "a9800bb0c4449251c92a1e60371ee77557b6620f3ea3ffffffffffcef8fb4ca7efc5"
        "433f591ecfc57391811ce1e186a3793024def5c884cba51d",
    ),
]


def psbtview():
    # a BIP-174 PSBT built by hand, so that the sequences of 0 reach the
    # view unchanged: PSBT.serialize() would write them as 0xFFFFFFFF (#146)
    raw = unhexlify(RAW_TX)
    psbt = b"psbt\xff\x01\x00" + compact.to_bytes(len(raw)) + raw + b"\x00"
    psbt += b"\x00" * (len(UTXOS) + 2)  # empty maps, 9 inputs and 2 outputs
    return PSBTView.view(BytesIO(psbt))


class SighashTaprootTest(TestCase):
    def check(self, tx):
        values = [value for value, _ in UTXOS]
        scripts = [Script(unhexlify(spk)) for _, spk in UTXOS]
        for i, sighash, expected in SIGHASHES:
            h = tx.sighash_taproot(i, scripts, values, sighash=sighash)
            self.assertEqual(hexlify(h).decode(), expected, "input %d" % i)

    def test_transaction(self):
        self.check(Transaction.parse(unhexlify(RAW_TX)))

    def test_psbtview(self):
        self.check(psbtview())

    def test_single_commits_to_the_hash_of_the_output(self):
        tx = Transaction.parse(unhexlify(RAW_TX))
        values = [value for value, _ in UTXOS]
        scripts = [Script(unhexlify(spk)) for _, spk in UTXOS]
        for i, sighash, sigmsg in SINGLE_SIGMSGS:
            msg = unhexlify(sigmsg)
            self.assertEqual(msg[-32:], hashes.sha256(tx.vout[i].serialize()))
            self.assertEqual(
                tx.sighash_taproot(i, scripts, values, sighash=sighash),
                hashes.tagged_hash("TapSighash", msg),
            )

    def test_single_without_a_corresponding_output(self):
        tx = Transaction.parse(unhexlify(RAW_TX))
        values = [value for value, _ in UTXOS]
        scripts = [Script(unhexlify(spk)) for _, spk in UTXOS]
        msg = "No corresponding output for SIGHASH_SINGLE"
        for i in [2, 8]:
            for sighash in [0x03, 0x83]:
                with self.assertRaises(TransactionError) as exc:
                    tx.sighash_taproot(i, scripts, values, sighash=sighash)
                self.assertEqual(str(exc.exception), msg)
                with self.assertRaises(PSBTError) as exc:
                    psbtview().sighash_taproot(i, scripts, values, sighash=sighash)
                self.assertEqual(str(exc.exception), msg)
