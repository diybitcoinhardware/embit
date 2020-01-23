try:
    import secp256k1
except:
    from . import ctypes_secp256k1 as secp256k1

from . import hashlib

try:
    from micropython import const
except:
    const = lambda x: x