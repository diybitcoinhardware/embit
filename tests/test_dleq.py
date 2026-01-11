"""
Tests for BIP-374 DLEQ proof verification and generation.
"""

import pytest
from os import urandom

from embit import ec
from embit.util import secp256k1

from dleq import (
    verify_dleq_proof,
    generate_dleq_proof,
    tagged_hash,
    SECP256K1_ORDER,
)


class TestTaggedHash:
    """Test BIP-340 style tagged hashing."""

    def test_deterministic(self):
        """Same inputs produce same output."""
        data = b"test data"
        h1 = tagged_hash("BIP0374/challenge", data)
        h2 = tagged_hash("BIP0374/challenge", data)
        assert h1 == h2
        assert len(h1) == 32

    def test_different_tags(self):
        """Different tags produce different outputs."""
        data = b"test data"
        h1 = tagged_hash("BIP0374/challenge", data)
        h2 = tagged_hash("other/tag", data)
        assert h1 != h2


class TestDLEQProofGeneration:
    """Test DLEQ proof generation."""

    def test_generate_proof_structure(self):
        """Generated proof has correct structure."""
        a = urandom(32)
        B = ec.PrivateKey(urandom(32)).get_public_key().sec()

        A, C, proof = generate_dleq_proof(a, B)

        assert len(A) == 33
        assert len(C) == 33
        assert len(proof) == 64
        assert A[0] in (0x02, 0x03)  # compressed pubkey prefix
        assert C[0] in (0x02, 0x03)

    def test_A_equals_aG(self):
        """A is correctly computed as a*G."""
        a = urandom(32)
        B = ec.PrivateKey(urandom(32)).get_public_key().sec()

        A, C, proof = generate_dleq_proof(a, B)

        # Compute expected A directly
        expected_A = ec.PrivateKey(a).get_public_key().sec()
        assert A == expected_A


class TestDLEQProofVerification:
    """Test DLEQ proof verification."""

    def test_valid_proof_verifies(self):
        """A correctly generated proof should verify."""
        a = urandom(32)
        B = ec.PrivateKey(urandom(32)).get_public_key().sec()

        A, C, proof = generate_dleq_proof(a, B)

        assert verify_dleq_proof(A, B, C, proof) is True

    def test_wrong_A_fails(self):
        """Proof fails if A doesn't match."""
        a = urandom(32)
        B = ec.PrivateKey(urandom(32)).get_public_key().sec()

        A, C, proof = generate_dleq_proof(a, B)

        # Use different A
        wrong_A = ec.PrivateKey(urandom(32)).get_public_key().sec()
        assert verify_dleq_proof(wrong_A, B, C, proof) is False

    def test_wrong_B_fails(self):
        """Proof fails if B doesn't match."""
        a = urandom(32)
        B = ec.PrivateKey(urandom(32)).get_public_key().sec()

        A, C, proof = generate_dleq_proof(a, B)

        # Use different B
        wrong_B = ec.PrivateKey(urandom(32)).get_public_key().sec()
        assert verify_dleq_proof(A, wrong_B, C, proof) is False

    def test_wrong_C_fails(self):
        """Proof fails if C doesn't match."""
        a = urandom(32)
        B = ec.PrivateKey(urandom(32)).get_public_key().sec()

        A, C, proof = generate_dleq_proof(a, B)

        # Use different C (ECDH with different key)
        wrong_C_parsed = secp256k1.ec_pubkey_parse(B)
        secp256k1.ec_pubkey_tweak_mul(wrong_C_parsed, urandom(32))
        wrong_C = secp256k1.ec_pubkey_serialize(wrong_C_parsed)

        assert verify_dleq_proof(A, B, wrong_C, proof) is False

    def test_tampered_proof_fails(self):
        """Tampered proof fails verification."""
        a = urandom(32)
        B = ec.PrivateKey(urandom(32)).get_public_key().sec()

        A, C, proof = generate_dleq_proof(a, B)

        # Tamper with proof (flip a bit)
        tampered = bytearray(proof)
        tampered[0] ^= 0x01
        tampered = bytes(tampered)

        assert verify_dleq_proof(A, B, C, tampered) is False

    def test_wrong_length_proof_fails(self):
        """Proof with wrong length fails."""
        a = urandom(32)
        B = ec.PrivateKey(urandom(32)).get_public_key().sec()

        A, C, _ = generate_dleq_proof(a, B)

        # Too short
        assert verify_dleq_proof(A, B, C, b'\x00' * 63) is False
        # Too long
        assert verify_dleq_proof(A, B, C, b'\x00' * 65) is False

    def test_s_greater_than_order_fails(self):
        """Proof with s >= curve order fails."""
        a = urandom(32)
        B = ec.PrivateKey(urandom(32)).get_public_key().sec()

        A, C, proof = generate_dleq_proof(a, B)

        # Create invalid proof with s = curve order
        e = proof[:32]
        invalid_s = SECP256K1_ORDER.to_bytes(32, 'big')
        invalid_proof = e + invalid_s

        assert verify_dleq_proof(A, B, C, invalid_proof) is False

    def test_e_greater_than_order_fails(self):
        """Proof with e >= curve order fails."""
        a = urandom(32)
        B = ec.PrivateKey(urandom(32)).get_public_key().sec()

        A, C, proof = generate_dleq_proof(a, B)

        # Create invalid proof with e = curve order
        invalid_e = SECP256K1_ORDER.to_bytes(32, 'big')
        s = proof[32:]
        invalid_proof = invalid_e + s

        assert verify_dleq_proof(A, B, C, invalid_proof) is False


class TestDLEQProofGenerationEdgeCases:
    """Test edge cases in proof generation."""

    def test_private_key_zero_fails(self):
        """Private key of zero should fail."""
        a = b'\x00' * 32
        B = ec.PrivateKey(urandom(32)).get_public_key().sec()

        with pytest.raises(ValueError, match="Private key must be in range"):
            generate_dleq_proof(a, B)

    def test_private_key_at_order_fails(self):
        """Private key >= curve order should fail."""
        a = SECP256K1_ORDER.to_bytes(32, 'big')
        B = ec.PrivateKey(urandom(32)).get_public_key().sec()

        with pytest.raises(ValueError, match="Private key must be in range"):
            generate_dleq_proof(a, B)

    def test_nonce_zero_fails(self):
        """Nonce that reduces to zero should fail."""
        a = urandom(32)
        B = ec.PrivateKey(urandom(32)).get_public_key().sec()
        k = b'\x00' * 32  # Will reduce to zero

        with pytest.raises(ValueError, match="Nonce reduced to zero"):
            generate_dleq_proof(a, B, k)


class TestDLEQRoundTrip:
    """Test generate -> verify round trip."""

    def test_multiple_round_trips(self):
        """Multiple random proofs all verify."""
        for _ in range(10):
            a = urandom(32)
            B = ec.PrivateKey(urandom(32)).get_public_key().sec()

            A, C, proof = generate_dleq_proof(a, B)
            assert verify_dleq_proof(A, B, C, proof) is True

    def test_deterministic_with_fixed_nonce(self):
        """Same inputs with same nonce produce same proof."""
        a = b'\x01' * 32
        B = ec.PrivateKey(b'\x02' * 32).get_public_key().sec()
        k = b'\x03' * 32

        A1, C1, proof1 = generate_dleq_proof(a, B, k)
        A2, C2, proof2 = generate_dleq_proof(a, B, k)

        assert A1 == A2
        assert C1 == C2
        assert proof1 == proof2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
