"""
BIP-374 DLEQ (Discrete Log Equality) proofs.

Implements generation and verification of DLEQ proofs as specified in
BIP-374. Used by BIP-375 Silent Payments to prove ECDH shares were
computed correctly.

A DLEQ proof demonstrates that the same scalar 'a' was used to compute:
- A = a * G (public key)
- C = a * B (ECDH shared point)

This allows a verifier to confirm an ECDH computation was done correctly
without learning the private key.

Follows the reference implementation, including the deterministic nonce
derivation via the BIP0374/aux and BIP0374/nonce tagged hashes and the
optional 32-byte message m in the challenge.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki
"""

from hashlib import sha256

from embit.util import secp256k1


# secp256k1 curve order
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# secp256k1 generator point, compressed SEC encoding
SECP256K1_G = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)


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


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _challenge(
    A: bytes, B: bytes, C: bytes, G: bytes, R1: bytes, R2: bytes, m: bytes
) -> int:
    """e = tagged_hash("BIP0374/challenge", A || B || C || G || R1 || R2 || m)

    All points must be compressed SEC encodings; m is b"" when absent.
    """
    e = tagged_hash("BIP0374/challenge", A + B + C + G + R1 + R2 + m)
    return int.from_bytes(e, "big")


def verify_dleq_proof(
    A: bytes,
    B: bytes,
    C: bytes,
    proof: bytes,
    G: bytes = None,
    m: bytes = None,
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
        m: Optional 32-byte message committed to by the proof
           (BIP-375 does not use it)

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
        if m is not None and len(m) != 32:
            return False
        m_prime = b"" if m is None else m

        # Parse proof components: e (challenge) || s (response)
        if len(proof) != 64:
            return False

        e = int.from_bytes(proof[:32], "big")
        s = int.from_bytes(proof[32:], "big")

        # Reject if e or s >= curve order (invalid proof)
        if e >= SECP256K1_ORDER or s >= SECP256K1_ORDER:
            return False

        # Parse the input points and normalize to compressed encodings,
        # since the challenge hash commits to compressed bytes
        A_parsed = secp256k1.ec_pubkey_parse(A)
        A_ser = secp256k1.ec_pubkey_serialize(A_parsed)
        B_parsed = secp256k1.ec_pubkey_parse(B)
        B_ser = secp256k1.ec_pubkey_serialize(B_parsed)
        C_parsed = secp256k1.ec_pubkey_parse(C)
        C_ser = secp256k1.ec_pubkey_serialize(C_parsed)

        G_parsed = secp256k1.ec_pubkey_parse(SECP256K1_G if G is None else G)
        G_ser = secp256k1.ec_pubkey_serialize(G_parsed)

        # NOTE: ec_pubkey_tweak_mul/negate/combine return the resulting
        # point (the pure-python backend cannot mutate in place); always
        # use the return value
        s_bytes = s.to_bytes(32, "big")
        e_bytes = e.to_bytes(32, "big")

        # Compute R1 = s*G - e*A
        sG = secp256k1.ec_pubkey_tweak_mul(
            secp256k1.ec_pubkey_parse(G_ser), s_bytes
        )
        eA = secp256k1.ec_pubkey_tweak_mul(
            secp256k1.ec_pubkey_parse(A_ser), e_bytes
        )
        neg_eA = secp256k1.ec_pubkey_negate(eA)
        # combine raises if the result is the point at infinity, which
        # verification must reject
        R1 = secp256k1.ec_pubkey_serialize(
            secp256k1.ec_pubkey_combine(sG, neg_eA)
        )

        # Compute R2 = s*B - e*C
        sB = secp256k1.ec_pubkey_tweak_mul(
            secp256k1.ec_pubkey_parse(B_ser), s_bytes
        )
        eC = secp256k1.ec_pubkey_tweak_mul(
            secp256k1.ec_pubkey_parse(C_ser), e_bytes
        )
        neg_eC = secp256k1.ec_pubkey_negate(eC)
        R2 = secp256k1.ec_pubkey_serialize(
            secp256k1.ec_pubkey_combine(sB, neg_eC)
        )

        # Verify: e == e'
        return e == _challenge(A_ser, B_ser, C_ser, G_ser, R1, R2, m_prime)

    except Exception:
        return False


def generate_dleq_proof(
    a: bytes,
    B: bytes,
    r: bytes = None,
    G: bytes = None,
    m: bytes = None,
) -> tuple:
    """
    Generate a BIP-374 DLEQ proof.

    Proves knowledge of scalar 'a' such that A = a*G and C = a*B.

    The nonce is derived deterministically per BIP-374 from the secret,
    the auxiliary randomness r, the points A and C, and the message m,
    via the BIP0374/aux and BIP0374/nonce tagged hashes. This protects
    against nonce reuse (which would leak 'a') even with a broken RNG.

    Args:
        a: 32-byte private key scalar
        B: 33-byte compressed public key (the base point for ECDH)
        r: Optional 32-byte auxiliary randomness (fresh randomness is
           generated if not provided)
        G: Optional 33-byte generator point (uses secp256k1 generator if None)
        m: Optional 32-byte message to commit to (BIP-375 does not use it)

    Returns:
        Tuple of (A, C, proof) where:
        - A: 33-byte compressed pubkey = a*G
        - C: 33-byte compressed ECDH point = a*B
        - proof: 64-byte DLEQ proof (e || s)

    Raises:
        ValueError: if a is not in [1, n), or B/G is not a valid point,
            or r/m has the wrong length

    Example:
        >>> from os import urandom
        >>> a = urandom(32)  # sender's private key
        >>> B = recipient_scan_pubkey
        >>> A, C, proof = generate_dleq_proof(a, B)
        >>> # Include C and proof in BIP-375 PSBT fields
    """
    from os import urandom

    if len(a) != 32:
        raise ValueError("Private key must be 32 bytes")
    a_int = int.from_bytes(a, "big")
    if not (0 < a_int < SECP256K1_ORDER):
        raise ValueError("Private key out of range")
    if r is None:
        r = urandom(32)
    if len(r) != 32:
        raise ValueError("Auxiliary randomness must be 32 bytes")
    if m is not None and len(m) != 32:
        raise ValueError("Message must be 32 bytes")
    m_prime = b"" if m is None else m

    G_ser = secp256k1.ec_pubkey_serialize(
        secp256k1.ec_pubkey_parse(SECP256K1_G if G is None else G)
    )
    B_ser = secp256k1.ec_pubkey_serialize(secp256k1.ec_pubkey_parse(B))

    # Compute A = a*G
    A = secp256k1.ec_pubkey_serialize(
        secp256k1.ec_pubkey_tweak_mul(secp256k1.ec_pubkey_parse(G_ser), a)
    )

    # Compute C = a*B
    C = secp256k1.ec_pubkey_serialize(
        secp256k1.ec_pubkey_tweak_mul(secp256k1.ec_pubkey_parse(B_ser), a)
    )

    # Deterministic nonce per BIP-374:
    # t = a XOR tagged_hash("BIP0374/aux", r)
    # k = int(tagged_hash("BIP0374/nonce", t || A || C || m)) mod n
    t = _xor_bytes(a, tagged_hash("BIP0374/aux", r))
    rand = tagged_hash("BIP0374/nonce", t + A + C + m_prime)
    k = int.from_bytes(rand, "big") % SECP256K1_ORDER
    if k == 0:
        raise ValueError("Invalid nonce")
    k_bytes = k.to_bytes(32, "big")

    # R1 = k*G
    R1 = secp256k1.ec_pubkey_serialize(
        secp256k1.ec_pubkey_tweak_mul(secp256k1.ec_pubkey_parse(G_ser), k_bytes)
    )

    # R2 = k*B
    R2 = secp256k1.ec_pubkey_serialize(
        secp256k1.ec_pubkey_tweak_mul(secp256k1.ec_pubkey_parse(B_ser), k_bytes)
    )

    e = _challenge(A, B_ser, C, G_ser, R1, R2, m_prime)

    # s = k + e*a (mod n)
    s = (k + e * a_int) % SECP256K1_ORDER

    proof = e.to_bytes(32, "big") + s.to_bytes(32, "big")

    # Self-check before returning, as the reference implementation does
    if not verify_dleq_proof(A, B_ser, C, proof, G=G, m=m):
        raise RuntimeError("Generated proof failed self-verification")

    return A, C, proof
