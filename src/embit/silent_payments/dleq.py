"""
BIP-374 DLEQ (Discrete Log Equality Proofs).

Given points A = a*G and C = a*B, proves knowledge of scalar a
across both bases (G and B) without revealing a.

Spec:     https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki
Reference: https://github.com/bitcoin/bips/blob/master/bip-0374/reference.py
"""

from .. import hashes
from ..util.key import SECP256K1_ORDER, SECP256K1_G
from ..util.secp256k1 import (
    ec_pubkey_create,
    ec_pubkey_parse,
    ec_pubkey_serialize,
    ec_pubkey_tweak_mul,
    ec_pubkey_combine,
    EC_COMPRESSED,
)

_G_COMPRESSED = b"\x02" + SECP256K1_G[0].to_bytes(32, "big")
DLEQ_TAG_AUX = "BIP0374/aux"
DLEQ_TAG_NONCE = "BIP0374/nonce"
DLEQ_TAG_CHALLENGE = "BIP0374/challenge"


class DLEQError(Exception):
    """Raised when DLEQ proof generation fails due to invalid inputs."""


def _scalar_mult_G(scalar_bytes, G_sec):
    """Return scalar * G_sec as an opaque pubkey handle.

    Uses ec_pubkey_create for the standard secp256k1 generator (fast path)
    and parse + tweak_mul for an arbitrary base point.
    Raises ValueError / OverflowError on invalid inputs.
    """
    if G_sec == _G_COMPRESSED:
        return ec_pubkey_create(scalar_bytes)
    # bytearray: tweak_mul mutates the point in place (required by the pure-Python
    # secp256k1 backend, which rejects immutable bytes; works with ctypes too)
    pub = bytearray(ec_pubkey_parse(G_sec))
    ec_pubkey_tweak_mul(pub, scalar_bytes)
    return pub


def generate_dleq_proof(a_bytes, B_sec, r=None, m=None, G=None):
    """
    Generate a 64-byte DLEQ proof (BIP-374 GenerateProof).

    Proves log_G(A) == log_B(C) without revealing scalar a,
    where A = a*G and C = a*B.

    Args:
        a_bytes: 32-byte private key scalar.
        B_sec:   33-byte compressed pubkey (alternative base point B).
        r:       32-byte auxiliary randomness. Must be fresh per proof; reusing r
                 with the same (a, B) and no m can leak a. When m is provided,
                 it is mixed into nonce generation, so that leak does not occur
                 if the reused r is paired with different messages, but fresh r
                 is still required.
        G:       Optional 33-byte compressed base point. Defaults to secp256k1 G.
                 BIP-374 footnote 2 allows any curve point as the generator so
                 the algorithm can be used with alternate bases on secp256k1.

    Returns:
        64-byte proof: bytes(32, e) || bytes(32, s).

    Raises:
        DLEQError: on invalid inputs or internal self-verification failure.
    """
    if len(a_bytes) != 32:
        raise DLEQError("a_bytes must be 32 bytes")
    if len(B_sec) != 33:
        raise DLEQError("B_sec must be a 33-byte compressed pubkey")
    if m is not None and len(m) != 32:
        raise DLEQError("m must be exactly 32 bytes per BIP-374")
    if G is not None and len(G) != 33:
        raise DLEQError("G must be a 33-byte compressed pubkey")

    G_sec = _G_COMPRESSED if G is None else G

    a_int = int.from_bytes(a_bytes, "big")
    if a_int == 0 or a_int >= SECP256K1_ORDER:
        raise DLEQError("a is out of range [1, n-1]")

    try:
        A_internal = _scalar_mult_G(a_bytes, G_sec)  # A = a*G
    except (ValueError, OverflowError):
        raise DLEQError("Invalid private key or G point")
    A_compressed = ec_pubkey_serialize(A_internal, EC_COMPRESSED)

    # C = a*B; ec_pubkey_parse rejects the point at infinity (spec is_infinite(B)).
    try:
        C_internal = bytearray(ec_pubkey_parse(B_sec))
        ec_pubkey_tweak_mul(C_internal, a_bytes)
    except (ValueError, OverflowError):
        raise DLEQError("Invalid B_sec")
    C_compressed = ec_pubkey_serialize(C_internal, EC_COMPRESSED)

    if r is None:
        raise DLEQError(
            "r must be provided: pass 32 bytes of fresh auxiliary randomness"
        )
    if len(r) != 32:
        raise DLEQError("r must be 32 bytes")

    aux_hash = hashes.tagged_hash(DLEQ_TAG_AUX, r)
    t_int = a_int ^ int.from_bytes(aux_hash, "big")
    t = t_int.to_bytes(32, "big")

    m_prime = m if m is not None else b""

    # k = H_nonce(t || cbytes(A) || cbytes(C) || m') mod n
    rand = hashes.tagged_hash(DLEQ_TAG_NONCE, t + A_compressed + C_compressed + m_prime)
    k = int.from_bytes(rand, "big") % SECP256K1_ORDER
    if k == 0:
        raise DLEQError("Derived nonce k is zero")

    k_bytes = k.to_bytes(32, "big")

    R1_internal = _scalar_mult_G(k_bytes, G_sec)  # R1 = k*G
    R1_compressed = ec_pubkey_serialize(R1_internal, EC_COMPRESSED)

    R2_internal = bytearray(ec_pubkey_parse(B_sec))  # R2 = k*B (fresh buffer)
    ec_pubkey_tweak_mul(R2_internal, k_bytes)
    R2_compressed = ec_pubkey_serialize(R2_internal, EC_COMPRESSED)

    # e = int(H_challenge(A || B || C || G || R1 || R2 || m'))
    e_hash = hashes.tagged_hash(
        DLEQ_TAG_CHALLENGE,
        A_compressed
        + B_sec
        + C_compressed
        + G_sec
        + R1_compressed
        + R2_compressed
        + m_prime,
    )
    e = int.from_bytes(e_hash, "big")

    s = (k + e * a_int) % SECP256K1_ORDER

    proof = e.to_bytes(32, "big") + s.to_bytes(32, "big")

    # self-verify before returning (as required by spec)
    if not verify_dleq_proof(A_compressed, B_sec, C_compressed, proof, m, G=G):
        raise DLEQError("Self-verification of generated proof failed")

    return proof


def verify_dleq_proof(A_sec, B_sec, C_sec, proof, m=None, G=None):
    """
    Verify a 64-byte DLEQ proof (BIP-374 VerifyProof).

    Returns True if the proof is valid, False otherwise.
    Never raises exceptions — all failures return False.

    Args:
        A_sec:  33-byte compressed pubkey (a*G).
        B_sec:  33-byte compressed pubkey (alternative base point B).
        C_sec:  33-byte compressed pubkey (a*B, the ECDH result).
        proof:  64-byte proof bytes.
        m:      Optional 32-byte message that was bound during generation.
        G:      33-byte compressed base point. Defaults to secp256k1 G.
                Must match the G used during proof generation.
    """
    if len(proof) != 64:
        return False
    if m is not None and len(m) != 32:
        return False

    G_sec = _G_COMPRESSED if G is None else G

    try:
        e = int.from_bytes(proof[:32], "big")
        s = int.from_bytes(proof[32:], "big")

        if s >= SECP256K1_ORDER:
            return False

        neg_e = (-e) % SECP256K1_ORDER
        if neg_e == 0:
            return False

        m_prime = m if m is not None else b""
        s_bytes = s.to_bytes(32, "big")
        neg_e_bytes = neg_e.to_bytes(32, "big")

        # ec_pubkey_parse rejects the point at infinity (spec is_infinite checks
        # for A, B, C).  ec_pubkey_combine raises ValueError when R1 or R2 would
        # be the point at infinity (spec is_infinite(R1) / is_infinite(R2)).
        # ec_pubkey_tweak_mul mutates in-place; each point gets a fresh buffer.

        # R1 = s*G + (-e)*A
        sG_internal = _scalar_mult_G(s_bytes, G_sec)
        neg_eA_internal = bytearray(ec_pubkey_parse(A_sec))
        ec_pubkey_tweak_mul(neg_eA_internal, neg_e_bytes)
        R1_internal = ec_pubkey_combine(sG_internal, neg_eA_internal)
        R1_compressed = ec_pubkey_serialize(R1_internal, EC_COMPRESSED)

        # R2 = s*B + (-e)*C
        sB_internal = bytearray(ec_pubkey_parse(B_sec))
        ec_pubkey_tweak_mul(sB_internal, s_bytes)
        neg_eC_internal = bytearray(ec_pubkey_parse(C_sec))
        ec_pubkey_tweak_mul(neg_eC_internal, neg_e_bytes)
        R2_internal = ec_pubkey_combine(sB_internal, neg_eC_internal)
        R2_compressed = ec_pubkey_serialize(R2_internal, EC_COMPRESSED)

        # Recompute e' = int(H_challenge(A || B || C || G || R1 || R2 || m'))
        e_check = int.from_bytes(
            hashes.tagged_hash(
                DLEQ_TAG_CHALLENGE,
                A_sec + B_sec + C_sec + G_sec + R1_compressed + R2_compressed + m_prime,
            ),
            "big",
        )

        return e == e_check

    except (ValueError, OverflowError):
        return False
