import sys
if sys.implementation.name == 'micropython':
    import hashlib
else:
    from .util import hashlib

def double_sha256(msg):
    """sha256(sha256(msg)) -> bytes"""
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()

def hash160(msg):
    """ripemd160(sha256(msg)) -> bytes"""
    return hashlib.ripemd160(hashlib.sha256(msg).digest()).digest()

def sha256(msg):
    """one-line sha256(msg) -> bytes"""
    return hashlib.sha256(msg).digest()

def ripemd160(msg):
    """one-line rmd160(msg) -> bytes"""
    return hashlib.ripemd160(msg).digest()