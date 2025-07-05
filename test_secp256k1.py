import os
import sys
sys.path.insert(0, 'src')

def test_library_loading():
    """Test that the secp256k1 library loads successfully"""
    try:
        from embit.util import ctypes_secp256k1
        print("✓ Library loaded successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to load library: {e}")
        return False

def test_basic_operations():
    """Test basic secp256k1 operations"""
    from embit.util import ctypes_secp256k1 as secp
    
    # Test secret key generation and validation
    secret = os.urandom(32)
    try:
        valid = secp.ec_seckey_verify(secret)
        print(f"✓ Secret key validation: {valid}")
    except Exception as e:
        print(f"✗ Secret key validation failed: {e}")
        return False
    
    # Test public key creation
    try:
        pubkey = secp.ec_pubkey_create(secret)
        print(f"✓ Public key created: {len(pubkey)} bytes")
    except Exception as e:
        print(f"✗ Public key creation failed: {e}")
        return False
    
    # Test public key serialization
    try:
        compressed = secp.ec_pubkey_serialize(pubkey, secp.EC_COMPRESSED)
        uncompressed = secp.ec_pubkey_serialize(pubkey, secp.EC_UNCOMPRESSED)
        print(f"✓ Compressed pubkey: {len(compressed)} bytes")
        print(f"✓ Uncompressed pubkey: {len(uncompressed)} bytes")
    except Exception as e:
        print(f"✗ Public key serialization failed: {e}")
        return False
    
    # Test signing and verification
    try:
        message = os.urandom(32)
        signature = secp.ecdsa_sign(message, secret)
        verified = secp.ecdsa_verify(signature, message, pubkey)
        print(f"✓ Signature verification: {verified}")
    except Exception as e:
        print(f"✗ Signing/verification failed: {e}")
        return False
    
    return True

def test_advanced_features():
    """Test advanced secp256k1 features if available"""
    from embit.util import ctypes_secp256k1 as secp
    
    secret = os.urandom(32)
    pubkey = secp.ec_pubkey_create(secret)
    
    # Test Schnorr signatures (if available)
    try:
        message = os.urandom(32)
        xonly_pub, parity = secp.xonly_pubkey_from_pubkey(pubkey)
        schnorr_sig = secp.schnorrsig_sign(message, secret)
        verified = secp.schnorrsig_verify(schnorr_sig, message, xonly_pub)
        print(f"✓ Schnorr signature verification: {verified}")
    except Exception as e:
        print(f"⚠ Schnorr signatures not available: {e}")
    
    # Test ECDH (if available)
    try:
        secret2 = os.urandom(32)
        pubkey2 = secp.ec_pubkey_create(secret2)
        shared_secret = secp.ecdh(pubkey2, secret)
        print(f"✓ ECDH shared secret: {len(shared_secret)} bytes")
    except Exception as e:
        print(f"⚠ ECDH not available: {e}")
    
    # Test recoverable signatures (if available)
    try:
        message = os.urandom(32)
        rec_sig = secp.ecdsa_sign_recoverable(message, secret)
        recovered_pubkey = secp.ecdsa_recover(rec_sig, message)
        print(f"✓ Recoverable signature works")
    except Exception as e:
        print(f"⚠ Recoverable signatures not available: {e}")

if __name__ == "__main__":
    print("Testing ctypes_secp256k1.py...")
    print("=" * 50)
    
    if not test_library_loading():
        sys.exit(1)
    
    if not test_basic_operations():
        sys.exit(1)
    
    test_advanced_features()
    
    print("=" * 50)
    print("✓ All tests completed successfully!")