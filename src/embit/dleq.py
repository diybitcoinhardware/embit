"""
BIP-374 DLEQ (Discrete Log Equality) Proof Verification

Implements verification of DLEQ proofs as specified in BIP-374.
Used by BIP-375 Silent Payments to prove ECDH shares were computed correctly.

A DLEQ proof demonstrates that the same private key 'a' was used to compute:
- A = a * G (public key)
- C = a * B (ECDH shared point)

This allows a verifier to confirm an ECDH computation was done correctly
without learning the private key.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki
"""

from hashlib import sha256
from typing import Optional

from embit import ec
from embit.util import secp256k1


# secp256k1 curve order
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def tagged_hash(tag: str, data: bytes) -> bytes:
    """
    BIP-340 style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)

    Args:
        tag: The tag string (e.g., "BIP0374/challenge")
        data: The data to hash

    Returns:
        32-byte hash
    """
    tag_hash = sha256(tag.encode()).digest()
    return sha256(tag_hash + tag_hash + data).digest()


def verify_dleq_proof(
    A: bytes,
    B: bytes,
    C: bytes,
    proof: bytes,
    G: Optional[bytes] = None
) -> bool:
    """
    Verify a BIP-374 DLEQ proof.

    Verifies that the same scalar 'a' was used to compute:
    - A = a * G (public key)
    - C = a * B (ECDH shared point)

    This proves the ECDH share was computed correctly without revealing 'a'.

    Args:
        A: 33-byte compressed public key (the signer's pubkey, or sum of input pubkeys)
        B: 33-byte compressed public key (recipient's scan key B_scan)
        C: 33-byte compressed ECDH share point
        proof: 64-byte DLEQ proof (32-byte challenge e || 32-byte response s)
        G: Optional 33-byte generator point (uses secp256k1 generator if None)

    Returns:
        True if proof is valid, False otherwise

    Example:
        >>> # Given a BIP-375 PSBT with DLEQ proof
        >>> A = sender_pubkey  # or sum of input pubkeys
        >>> B = recipient_scan_key
        >>> C = ecdh_share_from_psbt
        >>> proof = dleq_proof_from_psbt
        >>> if verify_dleq_proof(A, B, C, proof):
        ...     print("ECDH share verified!")
    """
    try:
        # Parse proof components: e (challenge) || s (response)
        if len(proof) != 64:
            return False

        e = int.from_bytes(proof[:32], 'big')
        s = int.from_bytes(proof[32:], 'big')

        # Reject if e or s >= curve order (invalid proof)
        if e >= SECP256K1_ORDER or s >= SECP256K1_ORDER:
            return False

        # Parse the input points
        A_parsed = secp256k1.ec_pubkey_parse(A)
        B_parsed = secp256k1.ec_pubkey_parse(B)
        C_parsed = secp256k1.ec_pubkey_parse(C)

        # Get generator G (derive from privkey=1 if not provided)
        if G is None:
            G_point = ec.PrivateKey(b'\x00' * 31 + b'\x01').get_public_key().sec()
            G_parsed = secp256k1.ec_pubkey_parse(G_point)
        else:
            G_parsed = secp256k1.ec_pubkey_parse(G)
            G_point = G

        # Compute R1 = s*G - e*A
        # First: s*G
        sG_parsed = secp256k1.ec_pubkey_parse(G_point)
        s_bytes = s.to_bytes(32, 'big')
        secp256k1.ec_pubkey_tweak_mul(sG_parsed, s_bytes)

        # Then: e*A
        eA_parsed = secp256k1.ec_pubkey_parse(A)
        e_bytes = e.to_bytes(32, 'big')
        secp256k1.ec_pubkey_tweak_mul(eA_parsed, e_bytes)

        # Negate e*A to get -e*A (for subtraction via addition)
        # NOTE: ec_pubkey_negate() returns a new point, does NOT modify in-place
        neg_eA = secp256k1.ec_pubkey_negate(eA_parsed)

        # R1 = s*G + (-e*A)
        R1_parsed = secp256k1.ec_pubkey_combine(sG_parsed, neg_eA)
        R1 = secp256k1.ec_pubkey_serialize(R1_parsed)

        # Compute R2 = s*B - e*C
        # First: s*B
        sB_parsed = secp256k1.ec_pubkey_parse(B)
        secp256k1.ec_pubkey_tweak_mul(sB_parsed, s_bytes)

        # Then: e*C
        eC_parsed = secp256k1.ec_pubkey_parse(C)
        secp256k1.ec_pubkey_tweak_mul(eC_parsed, e_bytes)

        # Negate e*C
        # NOTE: ec_pubkey_negate() returns a new point, does NOT modify in-place
        neg_eC = secp256k1.ec_pubkey_negate(eC_parsed)

        # R2 = s*B + (-e*C)
        R2_parsed = secp256k1.ec_pubkey_combine(sB_parsed, neg_eC)
        R2 = secp256k1.ec_pubkey_serialize(R2_parsed)

        # Compute challenge hash per BIP-374:
        # e' = tagged_hash("BIP0374/challenge", A || B || C || G || R1 || R2)
        challenge_data = A + B + C + G_point + R1 + R2
        e_computed = tagged_hash("BIP0374/challenge", challenge_data)
        e_computed_int = int.from_bytes(e_computed, 'big')

        # Verify: e == e'
        return e == e_computed_int

    except Exception:
        return False


def generate_dleq_proof(
    a: bytes,
    B: bytes,
    k: Optional[bytes] = None
) -> tuple:
    """
    Generate a BIP-374 DLEQ proof.

    Proves knowledge of scalar 'a' such that A = a*G and C = a*B.

    Args:
        a: 32-byte private key scalar
        B: 33-byte compressed public key (the base point for ECDH)
        k: Optional 32-byte nonce (randomly generated if not provided)

    Returns:
        Tuple of (A, C, proof) where:
        - A: 33-byte compressed pubkey = a*G
        - C: 33-byte compressed ECDH point = a*B
        - proof: 64-byte DLEQ proof

    Example:
        >>> from os import urandom
        >>> a = urandom(32)  # sender's private key
        >>> B = recipient_scan_pubkey
        >>> A, C, proof = generate_dleq_proof(a, B)
        >>> # Include C and proof in BIP-375 PSBT fields
    """
    from os import urandom

    # Compute A = a*G
    priv = ec.PrivateKey(a)
    A = priv.get_public_key().sec()

    # Compute C = a*B
    B_parsed = secp256k1.ec_pubkey_parse(B)
    C_parsed = secp256k1.ec_pubkey_parse(B)  # copy
    secp256k1.ec_pubkey_tweak_mul(C_parsed, a)
    C = secp256k1.ec_pubkey_serialize(C_parsed)

    # Get generator G
    G = ec.PrivateKey(b'\x00' * 31 + b'\x01').get_public_key().sec()

    # Generate nonce k (or use provided)
    if k is None:
        k = urandom(32)
    k_int = int.from_bytes(k, 'big') % SECP256K1_ORDER
    k_bytes = k_int.to_bytes(32, 'big')

    # R1 = k*G
    R1_priv = ec.PrivateKey(k_bytes)
    R1 = R1_priv.get_public_key().sec()

    # R2 = k*B
    R2_parsed = secp256k1.ec_pubkey_parse(B)
    secp256k1.ec_pubkey_tweak_mul(R2_parsed, k_bytes)
    R2 = secp256k1.ec_pubkey_serialize(R2_parsed)

    # e = tagged_hash("BIP0374/challenge", A || B || C || G || R1 || R2)
    challenge_data = A + B + C + G + R1 + R2
    e = tagged_hash("BIP0374/challenge", challenge_data)
    e_int = int.from_bytes(e, 'big')

    # s = k + e*a (mod n)
    a_int = int.from_bytes(a, 'big')
    s_int = (k_int + e_int * a_int) % SECP256K1_ORDER
    s = s_int.to_bytes(32, 'big')

    # Proof = e || s
    proof = e + s

    return A, C, proof
