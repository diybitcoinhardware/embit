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


def _point_mul(scalar_bytes, base_sec):
    """scalar * base → opaque pubkey handle. Fast path for secp256k1 generator G."""
    if base_sec == _G_COMPRESSED:
        return ec_pubkey_create(scalar_bytes)
    pub = bytearray(ec_pubkey_parse(base_sec))
    ec_pubkey_tweak_mul(pub, scalar_bytes)
    return pub


def _point_mul_or_inf(base_sec, scalar_int):
    """scalar * base → handle, or None (point at infinity) when scalar == 0."""
    if scalar_int == 0:
        return None
    return _point_mul(scalar_int.to_bytes(32, "big"), base_sec)


def _add_points(p1, p2):
    """p1 + p2, treating None as the point at infinity."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    return ec_pubkey_combine(p1, p2)


def _serialize(pub):
    """Compress an opaque pubkey handle to 33 bytes."""
    return ec_pubkey_serialize(pub, EC_COMPRESSED)


def generate_dleq_proof(a_bytes, B_sec, r=None, m=None, G=None):
    """
    Generate a 64-byte DLEQ proof (BIP-374 GenerateProof).

    Proves log_G(A) == log_B(C) without revealing scalar a,
    where A = a*G and C = a*B.

    Args:
        a_bytes: 32-byte private key scalar.
        B_sec:   33-byte compressed pubkey (alternative base point B).
        r:       32-byte auxiliary randomness. Must be fresh per proof.
        m:       Optional 32-byte message bound during generation.
        G:       Optional 33-byte compressed base point. Defaults to secp256k1 G.

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
    if r is None or len(r) != 32:
        raise DLEQError("r must be provided as 32 bytes of fresh auxiliary randomness")

    G_sec = _G_COMPRESSED if G is None else G
    a_int = int.from_bytes(a_bytes, "big")
    if a_int == 0 or a_int >= SECP256K1_ORDER:
        raise DLEQError("a is out of range [1, n-1]")

    try:
        A_compressed = _serialize(_point_mul(a_bytes, G_sec))
        C_compressed = _serialize(_point_mul(a_bytes, B_sec))
    except (ValueError, OverflowError):
        raise DLEQError("Invalid private key or base point")

    t_int = a_int ^ int.from_bytes(hashes.tagged_hash(DLEQ_TAG_AUX, r), "big")
    m_prime = m if m is not None else b""

    nonce_preimage = t_int.to_bytes(32, "big") + A_compressed + C_compressed + m_prime
    k = (
        int.from_bytes(hashes.tagged_hash(DLEQ_TAG_NONCE, nonce_preimage), "big")
        % SECP256K1_ORDER
    )
    if k == 0:
        raise DLEQError("Derived nonce k is zero")

    k_bytes = k.to_bytes(32, "big")
    R1_compressed = _serialize(_point_mul(k_bytes, G_sec))
    R2_compressed = _serialize(_point_mul(k_bytes, B_sec))

    challenge_preimage = (
        A_compressed
        + B_sec
        + C_compressed
        + G_sec
        + R1_compressed
        + R2_compressed
        + m_prime
    )
    e = int.from_bytes(
        hashes.tagged_hash(DLEQ_TAG_CHALLENGE, challenge_preimage), "big"
    )
    s = (k + e * a_int) % SECP256K1_ORDER
    proof = e.to_bytes(32, "big") + s.to_bytes(32, "big")

    if not verify_dleq_proof(A_compressed, B_sec, C_compressed, proof, m, G=G):
        raise DLEQError("Self-verification of generated proof failed")
    return proof


def verify_dleq_proof(A_sec, B_sec, C_sec, proof, m=None, G=None):
    """Verify a 64-byte DLEQ proof (BIP-374 VerifyProof)."""

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
        m_prime = m if m is not None else b""

        R1 = _add_points(_point_mul_or_inf(G_sec, s), _point_mul_or_inf(A_sec, neg_e))
        if R1 is None:
            return False
        R2 = _add_points(_point_mul_or_inf(B_sec, s), _point_mul_or_inf(C_sec, neg_e))
        if R2 is None:
            return False

        e_check = int.from_bytes(
            hashes.tagged_hash(
                DLEQ_TAG_CHALLENGE,
                A_sec
                + B_sec
                + C_sec
                + G_sec
                + _serialize(R1)
                + _serialize(R2)
                + m_prime,
            ),
            "big",
        )
        return e == e_check
    except (ValueError, OverflowError):
        return False
