try:
    # if it's micropython
    from micropython import const
    from secp256k1 import *
except:
    # we are in python
    try:
        # try ctypes bindings
        from . import ctypes_secp256k1 as secp256k1
    except:
        # fallback to python version
        from . import py_secp256k1 as secp256k1
