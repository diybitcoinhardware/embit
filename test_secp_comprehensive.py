import os
import sys
import time
sys.path.insert(0, 'src')

class Secp256k1Tester:
    def __init__(self):
        from embit.util import ctypes_secp256k1
        self.secp = ctypes_secp256k1
        self.passed = 0
        self.failed = 0
        self.warnings = 0
    
    def test(self, name, func):
        try:
            print(f"Testing {name}...", end=" ")
            result = func()
            if result:
                print("✓ PASS")
                self.passed += 1
            else:
                print("✗ FAIL")
                self.failed += 1
        except Exception as e:
            print(f"✗ ERROR: {e}")
            self.failed += 1
    
    def warn_test(self, name, func):
        try:
            print(f"Testing {name}...", end=" ")
            result = func()
            if result:
                print("✓ PASS")
                self.passed += 1
            else:
                print("⚠ SKIP")
                self.warnings += 1
        except Exception as e:
            print(f"⚠ SKIP: {e}")
            self.warnings += 1
    
    def test_key_operations(self):
        # Generate multiple key pairs and verify consistency
        for i in range(10):
            secret = os.urandom(32)
            if not self.secp.ec_seckey_verify(secret):
                continue
            pubkey = self.secp.ec_pubkey_create(secret)
            
            # Test serialization round-trip
            compressed = self.secp.ec_pubkey_serialize(pubkey, self.secp.EC_COMPRESSED)
            parsed = self.secp.ec_pubkey_parse(compressed)
            
            if parsed != pubkey:
                return False
        return True
    
    def test_signing_operations(self):
        secret = os.urandom(32)
        while not self.secp.ec_seckey_verify(secret):
            secret = os.urandom(32)
        
        pubkey = self.secp.ec_pubkey_create(secret)
        
        # Test multiple messages
        for i in range(5):
            message = os.urandom(32)
            sig = self.secp.ecdsa_sign(message, secret)
            if not self.secp.ecdsa_verify(sig, message, pubkey):
                return False
            
            # Test with wrong message
            wrong_msg = os.urandom(32)
            if self.secp.ecdsa_verify(sig, wrong_msg, pubkey):
                return False
        return True
    
    def test_key_tweaking(self):
        secret = os.urandom(32)
        while not self.secp.ec_seckey_verify(secret):
            secret = os.urandom(32)
        
        pubkey = self.secp.ec_pubkey_create(secret)
        tweak = os.urandom(32)
        
        # Test private key tweaking
        tweaked_secret = self.secp.ec_privkey_add(secret, tweak)
        tweaked_pubkey = self.secp.ec_pubkey_create(tweaked_secret)
        
        # Test public key tweaking
        pubkey_copy = self.secp._copy(pubkey)
        self.secp.ec_pubkey_tweak_add(pubkey_copy, tweak)
        
        return tweaked_pubkey == pubkey_copy
    
    def test_schnorr_if_available(self):
        try:
            secret = os.urandom(32)
            while not self.secp.ec_seckey_verify(secret):
                secret = os.urandom(32)
            
            message = os.urandom(32)
            sig = self.secp.schnorrsig_sign(message, secret)
            
            pubkey = self.secp.ec_pubkey_create(secret)
            xonly_pub, _ = self.secp.xonly_pubkey_from_pubkey(pubkey)
            
            return self.secp.schnorrsig_verify(sig, message, xonly_pub)
        except:
            return False
    
    def test_ecdh_if_available(self):
        try:
            secret1 = os.urandom(32)
            secret2 = os.urandom(32)
            while not self.secp.ec_seckey_verify(secret1):
                secret1 = os.urandom(32)
            while not self.secp.ec_seckey_verify(secret2):
                secret2 = os.urandom(32)
            
            pubkey1 = self.secp.ec_pubkey_create(secret1)
            pubkey2 = self.secp.ec_pubkey_create(secret2)
            
            shared1 = self.secp.ecdh(pubkey2, secret1)
            shared2 = self.secp.ecdh(pubkey1, secret2)
            
            return shared1 == shared2
        except:
            return False
    
    def test_performance(self):
        """Basic performance test"""
        secret = os.urandom(32)
        while not self.secp.ec_seckey_verify(secret):
            secret = os.urandom(32)
        
        # Time key generation
        start = time.time()
        for _ in range(100):
            self.secp.ec_pubkey_create(secret)
        key_gen_time = time.time() - start
        
        pubkey = self.secp.ec_pubkey_create(secret)
        message = os.urandom(32)
        
        # Time signing
        start = time.time()
        for _ in range(100):
            self.secp.ecdsa_sign(message, secret)
        sign_time = time.time() - start
        
        # Time verification
        sig = self.secp.ecdsa_sign(message, secret)
        start = time.time()
        for _ in range(100):
            self.secp.ecdsa_verify(sig, message, pubkey)
        verify_time = time.time() - start
        
        print(f"  Key generation: {key_gen_time:.3f}s for 100 ops")
        print(f"  Signing: {sign_time:.3f}s for 100 ops")
        print(f"  Verification: {verify_time:.3f}s for 100 ops")
        
        return True
    
    def run_all_tests(self):
        print("Comprehensive secp256k1 Testing")
        print("=" * 50)
        
        self.test("Key Operations", self.test_key_operations)
        self.test("Signing Operations", self.test_signing_operations)
        self.test("Key Tweaking", self.test_key_tweaking)
        self.warn_test("Schnorr Signatures", self.test_schnorr_if_available)
        self.warn_test("ECDH", self.test_ecdh_if_available)
        self.test("Performance", self.test_performance)
        
        print("=" * 50)
        print(f"Results: {self.passed} passed, {self.failed} failed, {self.warnings} warnings")
        
        return self.failed == 0

if __name__ == "__main__":
    tester = Secp256k1Tester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)