"""Checks that hold for the pure-Python backend and for the loaded one alike:
BIP340 signing with and without auxiliary randomness, and DER parsing of a
high-s ECDSA signature."""

from unittest import TestCase

from embit.util import py_secp256k1, secp256k1
from embit.util.key import SECP256K1_ORDER

# index, secret key, aux_rand, message, signature from BIP340's test vectors
BIP340_VECTORS = [
    (
        0,
        "0000000000000000000000000000000000000000000000000000000000000003",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
    ),
    (
        1,
        "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
        "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
    ),
    (
        2,
        "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
        "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
        "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
        "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B"
        "AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
    ),
]

# the pure-Python backend on its own, and embit.util.secp256k1, which is the
# ctypes backend where libsecp256k1 loads and the pure-Python one otherwise
BACKENDS = {"py": py_secp256k1, "loaded": secp256k1}


def _der(r, s):
    def integer(n):
        b = n.to_bytes((n.bit_length() + 8) // 8, "big")
        return b"\x02" + bytes([len(b)]) + b

    body = integer(r) + integer(s)
    return b"\x30" + bytes([len(body)]) + body


class BackendParityTest(TestCase):
    def test_bip340_vectors_with_aux(self):
        for name, backend in BACKENDS.items():
            for idx, sec, aux, msg, sig in BIP340_VECTORS:
                got = backend.schnorrsig_sign(
                    bytes.fromhex(msg), bytes.fromhex(sec), None, bytes.fromhex(aux)
                )
                self.assertEqual(got.hex().upper(), sig, (name, idx))

    def test_bip340_default_aux_is_zero_bytes(self):
        # vector 0 uses an all-zero aux, which is what a caller passing no aux gets
        idx, sec, aux, msg, sig = BIP340_VECTORS[0]
        for name, backend in BACKENDS.items():
            got = backend.schnorrsig_sign(bytes.fromhex(msg), bytes.fromhex(sec))
            self.assertEqual(got.hex().upper(), sig, name)

    def test_high_s_der_parses_and_normalizes(self):
        secret = b"1" * 32
        msg = b"q" * 32
        for name, backend in BACKENDS.items():
            low = backend.ecdsa_sign(msg, secret)
            r = int.from_bytes(low[:32], "little")
            s = int.from_bytes(low[32:], "little")
            high = _der(r, SECP256K1_ORDER - s)
            parsed = backend.ecdsa_signature_parse_der(high)
            self.assertEqual(
                int.from_bytes(parsed[32:], "little"), SECP256K1_ORDER - s, name
            )
            self.assertEqual(backend.ecdsa_signature_normalize(parsed), low, name)
            pub = backend.ec_pubkey_create(secret)
            self.assertTrue(backend.ecdsa_verify(low, msg, pub), name)
            self.assertFalse(backend.ecdsa_verify(parsed, msg, pub), name)
