"""Tests for BIP-374 DLEQ proof generation and verification.

Official test vectors embedded below are taken verbatim from
https://github.com/bitcoin/bips/tree/master/bip-0374
(test_vectors_generate_proof.csv and test_vectors_verify_proof.csv).
"""

from unittest import TestCase

from embit.dleq import (
    tagged_hash,
    generate_dleq_proof,
    verify_dleq_proof,
    SECP256K1_ORDER,
)
from embit.util import secp256k1


def _pubkey(sk: bytes) -> bytes:
    return secp256k1.ec_pubkey_serialize(secp256k1.ec_pubkey_create(sk))


# Deterministic stand-in for urandom so this module also runs under
# micropython (which has no os.urandom); the official vectors below carry
# the byte-exact coverage, these only need distinct valid scalars.
_counter = [0]


def _rand():
    _counter[0] += 1
    return tagged_hash("test/dleq", bytes([_counter[0]]))


# The vectors encode the point at infinity as the string INFINITY, which has
# no SEC encoding, so it cannot be passed to this byte-oriented API at all.
# The stand-in below is an invalid encoding that must be rejected the same
# way (the parser raises, generation fails).
INFINITY = "00" * 33

# index, point_G, scalar_a, point_B, auxrand_r, message, result_proof, comment
GENERATE_PROOF_VECTORS = [
    ("0", "02cef38f55e78b321a1f785cb1c6e33dfcef9784c18bdc4e279801c449ccdfb88e", "07ff93d43f1012a5d4a44aba55240212ed39c87b3344e46757d99f24177fc576", "02dad4b35c2379ba8334c9a5dda8f6e6d5cd575a7cc9d3ca4faaac51839daaa30f", "cb979b0fc8ccc7f237751e719d992fcc324b6500af33999cd54a3e5c05fb1ea4", "efb07d4b382d3da1079fbf24df623ba6c2e4c764993bbfa6dd7a4fe4aaf33859", "7e7e934169e0bf4706e6b29e5a621c7fe199a524744a25af80071e111c0e2e94118e730d8add118dd2ee4f7d1cc183e1b87168362d1a6f85c16d8671a3fc7a8a", "Success case 1"),
    ("1", "02464e351831efedb755223cabbf664f10564b4742c725c023034bc928ed339e0e", "f4e9172285393c6ada994c811b3e50fc47e96421ea7e54f4a4e459528d4cf562", "03fe589b0fa23f060f6d4d1e76b9b19d5bb3db0e56d39a4303913de0e706463008", "75f12482b9209dae12230ea1f8bf69723a1b447d361db8f510dd9ab33556fd4c", "76184ce9eea5b339ebf5304b57452c1ada1466610f0a58574d6c496798cee04b", "6b4521a8363a7ebc5d95ac6ec6b64db81fcf21795187d7c4600c42b73fb4fb9870ab8d106c0fd2d292c1710e10437b20575ddb3cb32eb77a5618d94ddba600f2", "Success case 2"),
    ("2", "0222db2054fef98344352a13bc0304a71da7b5e9a2f7fd1f3c9f3519a3d9377fb7", "589476913e763b60d5c2a5bfb39230ec669caac1b44312e9bcd2d3f4473abfef", "03bc7a19970c812118f74ba659b491e00dade6096ff62d1afe032a92b8671498ed", "4da1c4c4b0f9db4eb6b2e5cb648d7e8a0aa35aa5c4ec4d07f096e0e03deca366", "66503623468a78cfcef47888c85e0010ecd897f441d263448bfc7a89b882ab20", "12aa2aa469b3c037871a09d18ab18d3840219b1ed169f6ef9deae6d927949884a459705ae89a57522224ce3482dee00a41ba511188ae60efdeb736223eb66e7b", "Success case 3"),
    ("3", "03dfa65bd3711eba75fa1996a0c1d95a4419bd835304152d9aa6efa590670f2af6", "24d0ed3fc189eb1b64e5dc9dd4af0f3c8c143b0c79cb5fcca0dfa08a11cc60a1", "03b51081323d38fb0b75f0c1ec6755fdb79c239c327ca11269fe68ba8a878b704e", "31a68d6db27f6404bbceff646ff1b26a34704a0105a36c5a845d0257cea19c9b", "f2996b3766d123a949e65541baf1d89d446360d05af51bd93f0445d8c472c952", "7907653d29c5722ae44510e7f2839f253450aefc833b7e0a3b38384032f847f2cf41136b2fe6a558ad125287d20c0117f2a30c4ac0c4cebbcfa1dd3a69d84200", "Success case 4"),
    ("4", "02b15de5a3aefcfe2473916c76e619b5800ac7250ef93a9e6e0dd1505104fc58e7", "73fffa796edb72d111b5e0bbda1608f098ac98120796f971b438691e1bfb7b96", "03a4692be176ff89a972de9cc407083096847b950d1cae72b947665a3d5f4c2f01", "1cdfb4d7cce5e50783299896a471a44e6aa2c5e2100d6c37987c6b40503c6162", "0ceb45f560f2cf6b76a139ffe2c47c5ca6d26d6a3a210e59f197413bbec040b4", "02277ca5a7acfe8ae13c2db4a8f74489d0ba100ed8b082381ddb6522c4510718ab88b8dbbd785c388ade79586cf6416f3c47a79670af84abccc788a5d9f2e327", "Success case 5"),
    ("5", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "c08ca8e0bb59769fc6a4e078456284e00ea34f65add988c246e1bba85824ccdc", "034bccb1c570ac1f3bc42d61fe35de605b99626501ccb20297e1acbbf2d7152aa1", "c8d7056abd4726eb5a0f198740af14d6c1f0c16e5d7a37eaec621b661e669ac4", "", "503562d36910cd2d61a4d07c8ff680265c713e63dde0dcb88e6ea3c58597bdc05b86db9af95eccc475ce2177f941c118fefed20227d4ce8ce9557cb008758de6", "Success case 6"),
    ("6", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "8e641ba6bf7f64eec76005a29585a5035376375f33e331215aedfe03b8e80e7a", "0231c64e3efa506fdad6aad0f6084d5f6739de7f448d7e66f9d22f842638f41d60", "02a7b2e2f5a5e9b1078dbb160502a32491fe80a091e91dd92cf77b0b7d90970f", "35841ca532846e1cdd23a3d107824343584f88eff580929469865eae8355ee3c", "5c7b27a33210750e9de8679d9f43497cf9f12ac642cde0a1fc26443aa2fc89bf71aabf7bac89f5d8a96cbe86daba155fa74d6f3e111136179e53b04eb6d7807f", "Success case 7"),
    ("7", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "cfb9a7ecc49bea4f2e2ee34c38a6f48b5cd5bd06f4e4d4ffb45905b3d26db842", "021cb81121a00f89769903305a367ad3cc02d5b402b12c026e06ac94bde28cd608", "d38466b77484154a3fcb3151094c1c8a845c73a3c036b3a8ebffd8ef62c9047f", "22616bb5fb2d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794", "78a5544afa75bf152653fe55fb76926f2f65131bf090972a0b0b37d310c28a6bde0e7bfacc10ac12d36f55316ba134b6ba0b844a65ae05cad53c0b296c6639bb", "Success case 8"),
    ("8", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "0000000000000000000000000000000000000000000000000000000000000000", "021cb81121a00f89769903305a367ad3cc02d5b402b12c026e06ac94bde28cd608", "d38466b77484154a3fcb3151094c1c8a845c73a3c036b3a8ebffd8ef62c9047f", "22616bb5fb2d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794", "INVALID", "Failure case (a=0)"),
    ("9", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", "021cb81121a00f89769903305a367ad3cc02d5b402b12c026e06ac94bde28cd608", "d38466b77484154a3fcb3151094c1c8a845c73a3c036b3a8ebffd8ef62c9047f", "22616bb5fb2d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794", "INVALID", "Failure case (a=N [group order])"),
    ("10", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "cfb9a7ecc49bea4f2e2ee34c38a6f48b5cd5bd06f4e4d4ffb45905b3d26db842", "INFINITY", "d38466b77484154a3fcb3151094c1c8a845c73a3c036b3a8ebffd8ef62c9047f", "22616bb5fb2d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794", "INVALID", "Failure case (B is point at infinity)"),
]

# index, point_G, point_A, point_B, point_C, proof, message, result, comment
VERIFY_PROOF_VECTORS = [
    ("0", "02cef38f55e78b321a1f785cb1c6e33dfcef9784c18bdc4e279801c449ccdfb88e", "02b540b22c2c5ef0dc886abdaad27498453d893265560bc08a187319af6f845f58", "02dad4b35c2379ba8334c9a5dda8f6e6d5cd575a7cc9d3ca4faaac51839daaa30f", "03fefe00951dcd0ef10b12523393c2b8113119de4fdeeab320694e96bdccd2775b", "7e7e934169e0bf4706e6b29e5a621c7fe199a524744a25af80071e111c0e2e94118e730d8add118dd2ee4f7d1cc183e1b87168362d1a6f85c16d8671a3fc7a8a", "efb07d4b382d3da1079fbf24df623ba6c2e4c764993bbfa6dd7a4fe4aaf33859", "TRUE", "Success case 1"),
    ("1", "02464e351831efedb755223cabbf664f10564b4742c725c023034bc928ed339e0e", "032baaf1b10845a51b551196984a91efe2adf9d41b92bec3927218e6e4ca344002", "03fe589b0fa23f060f6d4d1e76b9b19d5bb3db0e56d39a4303913de0e706463008", "031f59aa1df22190e00380d8c5941adf899f596593765a1251005fd24f2bf7c884", "6b4521a8363a7ebc5d95ac6ec6b64db81fcf21795187d7c4600c42b73fb4fb9870ab8d106c0fd2d292c1710e10437b20575ddb3cb32eb77a5618d94ddba600f2", "76184ce9eea5b339ebf5304b57452c1ada1466610f0a58574d6c496798cee04b", "TRUE", "Success case 2"),
    ("2", "0222db2054fef98344352a13bc0304a71da7b5e9a2f7fd1f3c9f3519a3d9377fb7", "026aa26fcd626f8f55295859e9f8dd1f103149dd64d77c2bbba1bcf33bb37ebaa2", "03bc7a19970c812118f74ba659b491e00dade6096ff62d1afe032a92b8671498ed", "035628d1a69910daef614c7cae68d71ece55c5908af2360629e25c1b7de21eeb4b", "12aa2aa469b3c037871a09d18ab18d3840219b1ed169f6ef9deae6d927949884a459705ae89a57522224ce3482dee00a41ba511188ae60efdeb736223eb66e7b", "66503623468a78cfcef47888c85e0010ecd897f441d263448bfc7a89b882ab20", "TRUE", "Success case 3"),
    ("3", "03dfa65bd3711eba75fa1996a0c1d95a4419bd835304152d9aa6efa590670f2af6", "031bf61ba89009ee1266c9003a72e8e07d77877678ccda7f15325aadcd64ed186b", "03b51081323d38fb0b75f0c1ec6755fdb79c239c327ca11269fe68ba8a878b704e", "02d1b1f37a80217ba73785babfa63251052775f9d3ca65060054033288b7a3f66b", "7907653d29c5722ae44510e7f2839f253450aefc833b7e0a3b38384032f847f2cf41136b2fe6a558ad125287d20c0117f2a30c4ac0c4cebbcfa1dd3a69d84200", "f2996b3766d123a949e65541baf1d89d446360d05af51bd93f0445d8c472c952", "TRUE", "Success case 4"),
    ("4", "02b15de5a3aefcfe2473916c76e619b5800ac7250ef93a9e6e0dd1505104fc58e7", "0296c8e00dda60bb5565b77371ff913091978646b58ccf218bc591f68a75232e6e", "03a4692be176ff89a972de9cc407083096847b950d1cae72b947665a3d5f4c2f01", "03a7a7f9527fd387c2b2ce0c76669d646c78a3b470a4b34d3a2dabafc8505ef472", "02277ca5a7acfe8ae13c2db4a8f74489d0ba100ed8b082381ddb6522c4510718ab88b8dbbd785c388ade79586cf6416f3c47a79670af84abccc788a5d9f2e327", "0ceb45f560f2cf6b76a139ffe2c47c5ca6d26d6a3a210e59f197413bbec040b4", "TRUE", "Success case 5"),
    ("5", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "02637b2c3ea8ca80b9caecc50f4134c86ae9cf7a269133e7afc71f30e3a3cda60c", "034bccb1c570ac1f3bc42d61fe35de605b99626501ccb20297e1acbbf2d7152aa1", "0285b826c8dd175805901906b6c9b4140a30cbcc94c6e7dcf36476038bf90d4718", "503562d36910cd2d61a4d07c8ff680265c713e63dde0dcb88e6ea3c58597bdc05b86db9af95eccc475ce2177f941c118fefed20227d4ce8ce9557cb008758de6", "", "TRUE", "Success case 6"),
    ("6", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "02983a72b4cb44d4322641a7b2001900cd6ae0908a610546c73ed126accdba0514", "0231c64e3efa506fdad6aad0f6084d5f6739de7f448d7e66f9d22f842638f41d60", "03af1bc14b384eda28398df6a7900e567c5b6f6613cafce5027b98be015286f71b", "5c7b27a33210750e9de8679d9f43497cf9f12ac642cde0a1fc26443aa2fc89bf71aabf7bac89f5d8a96cbe86daba155fa74d6f3e111136179e53b04eb6d7807f", "35841ca532846e1cdd23a3d107824343584f88eff580929469865eae8355ee3c", "TRUE", "Success case 7"),
    ("7", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "03611410561c35dae13135e4ad8094baac9bbcf2f4e18498181a8ff8a6d43be9d9", "021cb81121a00f89769903305a367ad3cc02d5b402b12c026e06ac94bde28cd608", "03d9a98624c0c74fc7eebd39ed84175f80d03c774908e75ca737a0745d1c64e20a", "78a5544afa75bf152653fe55fb76926f2f65131bf090972a0b0b37d310c28a6bde0e7bfacc10ac12d36f55316ba134b6ba0b844a65ae05cad53c0b296c6639bb", "22616bb5fb2d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794", "TRUE", "Success case 8"),
    ("8", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "03611410561c35dae13135e4ad8094baac9bbcf2f4e18498181a8ff8a6d43be9d9", "03d9a98624c0c74fc7eebd39ed84175f80d03c774908e75ca737a0745d1c64e20a", "021cb81121a00f89769903305a367ad3cc02d5b402b12c026e06ac94bde28cd608", "78a5544afa75bf152653fe55fb76926f2f65131bf090972a0b0b37d310c28a6bde0e7bfacc10ac12d36f55316ba134b6ba0b844a65ae05cad53c0b296c6639bb", "22616bb5fb2d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794", "FALSE", "Swapped points case 1"),
    ("9", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "021cb81121a00f89769903305a367ad3cc02d5b402b12c026e06ac94bde28cd608", "03611410561c35dae13135e4ad8094baac9bbcf2f4e18498181a8ff8a6d43be9d9", "03d9a98624c0c74fc7eebd39ed84175f80d03c774908e75ca737a0745d1c64e20a", "78a5544afa75bf152653fe55fb76926f2f65131bf090972a0b0b37d310c28a6bde0e7bfacc10ac12d36f55316ba134b6ba0b844a65ae05cad53c0b296c6639bb", "22616bb5fb2d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794", "FALSE", "Swapped points case 2"),
    ("10", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "021cb81121a00f89769903305a367ad3cc02d5b402b12c026e06ac94bde28cd608", "03d9a98624c0c74fc7eebd39ed84175f80d03c774908e75ca737a0745d1c64e20a", "03611410561c35dae13135e4ad8094baac9bbcf2f4e18498181a8ff8a6d43be9d9", "78a5544afa75bf152653fe55fb76926f2f65131bf090972a0b0b37d310c28a6bde0e7bfacc10ac12d36f55316ba134b6ba0b844a65ae05cad53c0b296c6639bb", "22616bb5fb2d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794", "FALSE", "Swapped points case 3"),
    ("11", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "03d9a98624c0c74fc7eebd39ed84175f80d03c774908e75ca737a0745d1c64e20a", "03611410561c35dae13135e4ad8094baac9bbcf2f4e18498181a8ff8a6d43be9d9", "021cb81121a00f89769903305a367ad3cc02d5b402b12c026e06ac94bde28cd608", "78a5544afa75bf152653fe55fb76926f2f65131bf090972a0b0b37d310c28a6bde0e7bfacc10ac12d36f55316ba134b6ba0b844a65ae05cad53c0b296c6639bb", "22616bb5fb2d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794", "FALSE", "Swapped points case 4"),
    ("12", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "03d9a98624c0c74fc7eebd39ed84175f80d03c774908e75ca737a0745d1c64e20a", "021cb81121a00f89769903305a367ad3cc02d5b402b12c026e06ac94bde28cd608", "03611410561c35dae13135e4ad8094baac9bbcf2f4e18498181a8ff8a6d43be9d9", "78a5544afa75bf152653fe55fb76926f2f65131bf090972a0b0b37d310c28a6bde0e7bfacc10ac12d36f55316ba134b6ba0b844a65ae05cad53c0b296c6639bb", "22616bb5fb2d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794", "FALSE", "Swapped points case 5"),
    ("13", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "03611410561c35dae13135e4ad8094baac9bbcf2f4e18498181a8ff8a6d43be9d9", "021cb81121a00f89769903305a367ad3cc02d5b402b12c026e06ac94bde28cd608", "03d9a98624c0c74fc7eebd39ed84175f80d03c774908e75ca737a0745d1c64e20a", "78a5544afa75bf152653fe55fb76926f2f65131ff090972a0b0b37d310c28a6bde0e7bfacc10ac12d36f55316ba134b6ba0b844a65ae05cad53c0b296c6639bb", "22616bb5fb2d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794", "FALSE", "Tampered proof (random bit-flip)"),
    ("14", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "03611410561c35dae13135e4ad8094baac9bbcf2f4e18498181a8ff8a6d43be9d9", "021cb81121a00f89769903305a367ad3cc02d5b402b12c026e06ac94bde28cd608", "03d9a98624c0c74fc7eebd39ed84175f80d03c774908e75ca737a0745d1c64e20a", "78a5544afa75bf152653fe55fb76926f2f65131bf090972a0b0b37d310c28a6bde0e7bfacc10ac12d36f55316ba134b6ba0b844a65ae05cad53c0b296c6639bb", "22616bb5fb6d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794", "FALSE", "Tampered message (random bit-flip)"),
]


class TaggedHashTest(TestCase):
    def test_deterministic(self):
        h1 = tagged_hash("BIP0374/challenge", b"data")
        h2 = tagged_hash("BIP0374/challenge", b"data")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 32)

    def test_different_tags(self):
        h1 = tagged_hash("BIP0374/aux", b"data")
        h2 = tagged_hash("BIP0374/nonce", b"data")
        self.assertNotEqual(h1, h2)


class GenerateProofTest(TestCase):
    def test_structure(self):
        a = _rand()
        B = _pubkey(_rand())
        A, C, proof = generate_dleq_proof(a, B)
        self.assertEqual(len(A), 33)
        self.assertEqual(len(C), 33)
        self.assertEqual(len(proof), 64)

    def test_A_equals_aG(self):
        a = _rand()
        B = _pubkey(_rand())
        A, C, proof = generate_dleq_proof(a, B)
        self.assertEqual(A, _pubkey(a))

    def test_deterministic_with_fixed_aux(self):
        a = _rand()
        B = _pubkey(_rand())
        r = _rand()
        self.assertEqual(
            generate_dleq_proof(a, B, r=r), generate_dleq_proof(a, B, r=r)
        )

    def test_different_aux_different_proof(self):
        a = _rand()
        B = _pubkey(_rand())
        A1, C1, proof1 = generate_dleq_proof(a, B, r=b"\x01" * 32)
        A2, C2, proof2 = generate_dleq_proof(a, B, r=b"\x02" * 32)
        self.assertEqual((A1, C1), (A2, C2))
        self.assertNotEqual(proof1, proof2)
        self.assertTrue(verify_dleq_proof(A1, B, C1, proof1))
        self.assertTrue(verify_dleq_proof(A2, B, C2, proof2))

    def test_message_changes_proof(self):
        a = _rand()
        B = _pubkey(_rand())
        r = _rand()
        m = _rand()
        _, _, proof_no_m = generate_dleq_proof(a, B, r=r)
        A, C, proof_m = generate_dleq_proof(a, B, r=r, m=m)
        self.assertNotEqual(proof_no_m, proof_m)
        self.assertTrue(verify_dleq_proof(A, B, C, proof_m, m=m))
        self.assertFalse(verify_dleq_proof(A, B, C, proof_m))
        self.assertFalse(verify_dleq_proof(A, B, C, proof_no_m, m=m))

    def test_private_key_zero_fails(self):
        B = _pubkey(_rand())
        with self.assertRaises(ValueError):
            generate_dleq_proof(b"\x00" * 32, B)

    def test_private_key_at_order_fails(self):
        B = _pubkey(_rand())
        a = SECP256K1_ORDER.to_bytes(32, "big")
        with self.assertRaises(ValueError):
            generate_dleq_proof(a, B)

    def test_bad_aux_length_fails(self):
        B = _pubkey(_rand())
        with self.assertRaises(ValueError):
            generate_dleq_proof(_rand(), B, r=b"\x01" * 31)

    def test_bad_message_length_fails(self):
        B = _pubkey(_rand())
        with self.assertRaises(ValueError):
            generate_dleq_proof(_rand(), B, m=b"\x01" * 31)

    def test_multiple_round_trips(self):
        for _ in range(5):
            a = _rand()
            B = _pubkey(_rand())
            A, C, proof = generate_dleq_proof(a, B)
            self.assertTrue(verify_dleq_proof(A, B, C, proof))


class VerifyProofTest(TestCase):
    def _proof(self):
        a = _rand()
        B = _pubkey(_rand())
        A, C, proof = generate_dleq_proof(a, B)
        return A, B, C, proof

    def test_wrong_A_fails(self):
        A, B, C, proof = self._proof()
        self.assertFalse(verify_dleq_proof(_pubkey(_rand()), B, C, proof))

    def test_wrong_B_fails(self):
        A, B, C, proof = self._proof()
        self.assertFalse(verify_dleq_proof(A, _pubkey(_rand()), C, proof))

    def test_wrong_C_fails(self):
        A, B, C, proof = self._proof()
        self.assertFalse(verify_dleq_proof(A, B, _pubkey(_rand()), proof))

    def test_tampered_proof_fails(self):
        A, B, C, proof = self._proof()
        tampered = bytes([proof[0] ^ 0x01]) + proof[1:]
        self.assertFalse(verify_dleq_proof(A, B, C, tampered))

    def test_wrong_length_proof_fails(self):
        A, B, C, proof = self._proof()
        self.assertFalse(verify_dleq_proof(A, B, C, proof[:63]))
        self.assertFalse(verify_dleq_proof(A, B, C, proof + b"\x00"))

    def test_s_at_order_fails(self):
        A, B, C, proof = self._proof()
        bad = proof[:32] + SECP256K1_ORDER.to_bytes(32, "big")
        self.assertFalse(verify_dleq_proof(A, B, C, bad))

    def test_e_at_order_fails(self):
        A, B, C, proof = self._proof()
        bad = SECP256K1_ORDER.to_bytes(32, "big") + proof[32:]
        self.assertFalse(verify_dleq_proof(A, B, C, bad))

    def test_bad_message_length_fails(self):
        A, B, C, proof = self._proof()
        self.assertFalse(verify_dleq_proof(A, B, C, proof, m=b"\x01" * 31))

    def test_invalid_point_fails(self):
        A, B, C, proof = self._proof()
        bad_point = bytes.fromhex(INFINITY)
        self.assertFalse(verify_dleq_proof(bad_point, B, C, proof))
        self.assertFalse(verify_dleq_proof(A, bad_point, C, proof))
        self.assertFalse(verify_dleq_proof(A, B, bad_point, proof))
        self.assertFalse(verify_dleq_proof(A, B, C, proof, G=bad_point))


class OfficialVectorsTest(TestCase):
    """Official BIP-374 test vectors, run byte-exact."""

    def test_generate_proof_vectors(self):
        for row in GENERATE_PROOF_VECTORS:
            index, G_hex, a_hex, B_hex, r_hex, m_hex, result, comment = row
            G = bytes.fromhex(INFINITY if G_hex == "INFINITY" else G_hex)
            B = bytes.fromhex(INFINITY if B_hex == "INFINITY" else B_hex)
            a = bytes.fromhex(a_hex)
            r = bytes.fromhex(r_hex)
            m = bytes.fromhex(m_hex) if m_hex else None
            if result == "INVALID":
                with self.assertRaises(ValueError, msg=comment):
                    generate_dleq_proof(a, B, r=r, G=G, m=m)
            else:
                A, C, proof = generate_dleq_proof(a, B, r=r, G=G, m=m)
                self.assertEqual(proof, bytes.fromhex(result), comment)
                self.assertTrue(
                    verify_dleq_proof(A, B, C, proof, G=G, m=m), comment
                )

    def test_verify_proof_vectors(self):
        for row in VERIFY_PROOF_VECTORS:
            index, G_hex, A_hex, B_hex, C_hex, proof_hex, m_hex, result, comment = row
            G = bytes.fromhex(INFINITY if G_hex == "INFINITY" else G_hex)
            A = bytes.fromhex(INFINITY if A_hex == "INFINITY" else A_hex)
            B = bytes.fromhex(INFINITY if B_hex == "INFINITY" else B_hex)
            C = bytes.fromhex(INFINITY if C_hex == "INFINITY" else C_hex)
            proof = bytes.fromhex(proof_hex)
            m = bytes.fromhex(m_hex) if m_hex else None
            self.assertEqual(
                verify_dleq_proof(A, B, C, proof, G=G, m=m),
                result == "TRUE",
                comment,
            )
