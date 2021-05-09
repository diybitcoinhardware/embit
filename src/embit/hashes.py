import sys
import hashlib

try:
    # in micropython hashlib.c we have optimized version of hmac_sha512
    from hashlib import hmac_sha512
except:
    import hmac
    def hmac_sha512(key, msg):
        return hmac.new(key, msg, digestmod=hashlib.sha512).digest()


def double_sha256(msg):
    """sha256(sha256(msg)) -> bytes"""
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()


def hash160(msg):
    """ripemd160(sha256(msg)) -> bytes"""
    return hashlib.new('ripemd160', hashlib.sha256(msg).digest()).digest()


def sha256(msg):
    """one-line sha256(msg) -> bytes"""
    return hashlib.sha256(msg).digest()


def ripemd160(msg):
    """one-line rmd160(msg) -> bytes"""
    return hashlib.new('ripemd160', msg).digest()


def tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP-Schnorr tag-specific key derivation"""
    hashtag = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(hashtag + hashtag + data).digest()
