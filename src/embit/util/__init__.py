from . import secp256k1
from . import hashlib

try:
    from micropython import const
except:
    const = lambda x: x
