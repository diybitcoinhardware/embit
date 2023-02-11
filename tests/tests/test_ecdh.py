from unittest import TestCase
from embit.ec import PublicKey, PrivateKey
import hashlib

class ECDHTest(TestCase):
    def test_one(self):
        """ECDH of privkey=1 and any pubkey should give sha256(pubkey)"""
        one = PrivateKey((1).to_bytes(32, 'big'))
        G = one.get_public_key()
        pk = PrivateKey(b"q"*32)
        pub = pk.get_public_key()
        s1 = pk.ecdh(G)
        s2 = one.ecdh(pub)
        self.assertEqual(s1, s2)
        expected = hashlib.sha256(pub.sec()).digest()
        self.assertEqual(s1, expected)

    def test_two(self):
        """Check that both parties get the same secret"""
        pk1 = PrivateKey(b"a"*32)
        pub1 = pk1.get_public_key()
        pk2 = PrivateKey(b"b"*32)
        pub2 = pk2.get_public_key()
        self.assertEqual(pk1.ecdh(pub2), pk2.ecdh(pub1))

    def test_hashfn(self):
        """
        Custom hash function that returns x coordinate
        instead of using sha256
        """
        one = PrivateKey((1).to_bytes(32, 'big'))
        G = one.get_public_key()
        pk = PrivateKey(b"b"*32)
        pub = pk.get_public_key()

        def hashfn(x, y, data=None):
            return x

        s1 = pk.ecdh(G, hashfn)
        s2 = one.ecdh(pub, hashfn, data=b"123")
        self.assertEqual(s1, s2)
        expected = pub.xonly()
        self.assertEqual(s1, expected)

    def test_hashfn_data(self):
        """
        Custom hash function that hashes x and data if provided
        """
        one = PrivateKey((1).to_bytes(32, 'big'))
        G = one.get_public_key()
        pk = PrivateKey(b"b"*32)
        pub = pk.get_public_key()

        def hashfn(x, y, data=None):
            h = hashlib.sha256(x)
            if data is not None:
                h.update(data)
            return h.digest()

        s1 = pk.ecdh(G, hashfn)
        expected1 = hashlib.sha256(pub.xonly()).digest()
        self.assertEqual(s1, expected1)

        s2 = one.ecdh(pub, hashfn, data=b"123")
        expected2 = hashlib.sha256(pub.xonly()+b"123").digest()
        self.assertEqual(s2, expected2)

    def test_raising_hashfn(self):
        """
        Custom hash function that returns x coordinate
        instead of using sha256
        """
        one = PrivateKey((1).to_bytes(32, 'big'))
        G = one.get_public_key()
        pk = PrivateKey(b"b"*32)
        pub = pk.get_public_key()

        def hashfn(x, y, data=None):
            if data is not None:
                raise ValueError("Something bad happened")
            return x

        s1 = pk.ecdh(G, hashfn)
        self.assertRaises(RuntimeError, one.ecdh, pub, hashfn, b"123")
        expected = pub.xonly()
        self.assertEqual(s1, expected)
