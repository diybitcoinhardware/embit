import ctypes, os
import ctypes.util
import platform

from ctypes import (
    byref, c_byte, c_int, c_uint, c_char_p, c_size_t, 
    c_void_p, create_string_buffer, CFUNCTYPE, POINTER
)

# Flags to pass to context_create.
CONTEXT_VERIFY = 0b0100000001
CONTEXT_SIGN =   0b1000000001
CONTEXT_NONE =   0b0000000001

# Flags to pass to ec_pubkey_serialize
EC_COMPRESSED =   0b0100000010
EC_UNCOMPRESSED = 0b0000000010

def _init(flags = (CONTEXT_SIGN | CONTEXT_VERIFY)):
    library_path = ctypes.util.find_library('libsecp256k1')
    # library search failed
    if not library_path:
        if platform.system() == "Linux" and os.path.isfile("/usr/local/lib/libsecp256k1.so.0"):
            library_path = "/usr/local/lib/libsecp256k1.so.0"
    # meh, can't find library
    if not library_path:
        raise RuntimeError("Can't find libsecp256k1 library. Make sure to compile and install it.")

    secp256k1 = ctypes.cdll.LoadLibrary(library_path)

    secp256k1.secp256k1_context_create.argtypes = [c_uint]
    secp256k1.secp256k1_context_create.restype = c_void_p

    secp256k1.secp256k1_context_randomize.argtypes = [c_void_p, c_char_p]
    secp256k1.secp256k1_context_randomize.restype = c_int

    
    secp256k1.secp256k1_ec_privkey_negate.argtypes = [c_void_p, c_char_p]
    secp256k1.secp256k1_ec_privkey_negate.restype = c_int
    
    secp256k1.secp256k1_ec_privkey_tweak_add.argtypes = [c_void_p, c_char_p, c_char_p]
    secp256k1.secp256k1_ec_privkey_tweak_add.restype = c_int

    secp256k1.secp256k1_ec_privkey_tweak_mul.argtypes = [c_void_p, c_char_p, c_char_p]
    secp256k1.secp256k1_ec_privkey_tweak_mul.restype = c_int

    
    secp256k1.secp256k1_ec_pubkey_create.argtypes = [c_void_p, c_void_p, c_char_p]
    secp256k1.secp256k1_ec_pubkey_create.restype = c_int

    secp256k1.secp256k1_ec_pubkey_parse.argtypes = [c_void_p, c_char_p, c_char_p, c_int]
    secp256k1.secp256k1_ec_pubkey_parse.restype = c_int

    secp256k1.secp256k1_ec_pubkey_serialize.argtypes = [c_void_p, c_char_p, c_void_p, c_char_p, c_uint]
    secp256k1.secp256k1_ec_pubkey_serialize.restype = c_int

    secp256k1.secp256k1_ec_pubkey_tweak_add.argtypes = [c_void_p, c_char_p, c_char_p]
    secp256k1.secp256k1_ec_pubkey_tweak_add.restype = c_int

    secp256k1.secp256k1_ec_pubkey_tweak_mul.argtypes = [c_void_p, c_char_p, c_char_p]
    secp256k1.secp256k1_ec_pubkey_tweak_mul.restype = c_int

    
    secp256k1.secp256k1_ecdsa_signature_parse_compact.argtypes = [c_void_p, c_char_p, c_char_p]
    secp256k1.secp256k1_ecdsa_signature_parse_compact.restype = c_int

    secp256k1.secp256k1_ecdsa_signature_serialize_compact.argtypes = [c_void_p, c_char_p, c_char_p]
    secp256k1.secp256k1_ecdsa_signature_serialize_compact.restype = c_int

    secp256k1.secp256k1_ecdsa_signature_parse_der.argtypes = [c_void_p, c_char_p, c_char_p, c_uint]
    secp256k1.secp256k1_ecdsa_signature_parse_der.restype = c_int

    secp256k1.secp256k1_ecdsa_signature_serialize_der.argtypes = [c_void_p, c_char_p, c_void_p, c_char_p]
    secp256k1.secp256k1_ecdsa_signature_serialize_der.restype = c_int

    secp256k1.secp256k1_ecdsa_sign.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p, c_void_p, c_void_p]
    secp256k1.secp256k1_ecdsa_sign.restype = c_int

    secp256k1.secp256k1_ecdsa_verify.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
    secp256k1.secp256k1_ecdsa_verify.restype = c_int

    secp256k1.secp256k1_ec_pubkey_combine.argtypes = [c_void_p, c_char_p, c_void_p, c_size_t]
    secp256k1.secp256k1_ec_pubkey_combine.restype = c_int

    # recoverable module
    secp256k1.secp256k1_ecdsa_sign_recoverable.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p, c_void_p, c_void_p]
    secp256k1.secp256k1_ecdsa_sign_recoverable.restype = c_int

    secp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact.argtypes = [c_void_p, c_char_p, c_char_p, c_int]
    secp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact.restype = c_int

    secp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
    secp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact.restype = c_int

    secp256k1.secp256k1_ecdsa_recoverable_signature_convert.argtypes = [c_void_p, c_char_p, c_char_p]
    secp256k1.secp256k1_ecdsa_recoverable_signature_convert.restype = c_int

    secp256k1.secp256k1_ecdsa_recover.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
    secp256k1.secp256k1_ecdsa_recover.restype = c_int

    secp256k1.ctx = secp256k1.secp256k1_context_create(flags)
    
    r = secp256k1.secp256k1_context_randomize(secp256k1.ctx, os.urandom(32))
    
    return secp256k1

_secp = _init()

# bindings equal to ones in micropython
def context_randomize(seed, context=_secp.ctx):
    if len(seed)!=32:
        raise ValueError("Seed should be 32 bytes long")
    if _secp.secp256k1_context_randomize(context, seed) == 0:
        raise RuntimeError("Failed to randomize context")

def ec_pubkey_create(secret, context=_secp.ctx):
    if len(secret)!=32:
        raise ValueError("Private key should be 32 bytes long")
    pub = bytes(64)
    r = _secp.secp256k1_ec_pubkey_create(context, pub, secret)
    if r == 0:
        raise ValueError("Invalid private key")
    return pub

def ec_pubkey_parse(sec, context=_secp.ctx):
    if len(sec)!=33 and len(sec)!= 65:
        raise ValueError("Serialized pubkey should be 33 or 65 bytes long")
    if len(sec)==33:
        if sec[0] != 0x02 and sec[0] != 0x03:
            raise ValueError("Compressed pubkey should start with 0x02 or 0x03")
    else:
        if sec[0] != 0x04:
            raise ValueError("Uncompressed pubkey should start with 0x04")
    pub = bytes(64)
    r = _secp.secp256k1_ec_pubkey_parse(context, pub, sec, len(sec))
    if r == 0:
        raise ValueError("Failed parsing public key")
    return pub

def ec_pubkey_serialize(pubkey, flag=EC_COMPRESSED, context=_secp.ctx):
    if len(pubkey)!=64:
        raise ValueError("Pubkey should be 64 bytes long")
    if flag not in [EC_COMPRESSED, EC_UNCOMPRESSED]:
        raise ValueError("Invalid flag")
    sec = bytes(33) if (flag == EC_COMPRESSED) else bytes(65)
    sz = c_size_t(len(sec))
    r = _secp.secp256k1_ec_pubkey_serialize(context, sec, byref(sz), pubkey, flag)
    if r == 0:
        raise ValueError("Failed to serialize pubkey")
    return sec

def ecdsa_signature_parse_compact(compact_sig, context=_secp.ctx):
    if len(compact_sig)!=64:
        raise ValueError("Compact signature should be 64 bytes long")
    sig = bytes(64)
    r = _secp.secp256k1_ecdsa_signature_parse_compact(context, sig, compact_sig)
    if r == 0:
        raise ValueError("Failed parsing compact signature")
    return sig

def ecdsa_signature_parse_der(der, context=_secp.ctx):
    sig = bytes(64)
    r = _secp.secp256k1_ecdsa_signature_parse_der(context, sig, der, len(der))
    if r == 0:
        raise ValueError("Failed parsing compact signature")
    return sig
    
def ecdsa_signature_serialize_der(sig, context=_secp.ctx):
    if len(sig)!=64:
        raise ValueError("Signature should be 64 bytes long")
    der = bytes(78) # max
    sz = c_size_t(len(der))
    r = _secp.secp256k1_ecdsa_signature_serialize_der(context, der, byref(sz), sig)
    if r == 0:
        raise ValueError("Failed serializing der signature")
    return der[:sz.value]

def ecdsa_signature_serialize_compact(sig, context=_secp.ctx):
    if len(sig)!=64:
        raise ValueError("Signature should be 64 bytes long")
    ser = bytes(64)
    r = _secp.secp256k1_ecdsa_signature_serialize_compact(context, ser, sig)
    if r == 0:
        raise ValueError("Failed serializing der signature")
    return ser
    
def ecdsa_signature_normalize(sig, context=_secp.ctx):
    if len(sig)!=64:
        raise ValueError("Signature should be 64 bytes long")
    sig2 = bytes(64)
    r = _secp.secp256k1_ecdsa_signature_normalize(context, sig2, sig)
    return sig2

def ecdsa_verify(sig, msg, pub, context=_secp.ctx):
    if len(sig)!=64:
        raise ValueError("Signature should be 64 bytes long")
    if len(msg)!=32:
        raise ValueError("Message should be 32 bytes long")
    if len(pub)!=64:
        raise ValueError("Public key should be 64 bytes long")
    r = _secp.secp256k1_ecdsa_verify(context, sig, msg, pub)
    return bool(r)

def ecdsa_sign(msg, secret, context=_secp.ctx):
    if len(msg)!=32:
        raise ValueError("Message should be 32 bytes long")
    if len(secret)!=32:
        raise ValueError("Secret key should be 32 bytes long")
    sig = bytes(64)
    r = _secp.secp256k1_ecdsa_sign(context, sig, msg, secret, None, None)
    if r == 0:
        raise ValueError("Failed to sign")
    return sig

def ec_seckey_verify(secret, context=_secp.ctx):
    if len(secret)!=32:
        raise ValueError("Secret should be 32 bytes long")
    return bool(_secp.secp256k1_ec_seckey_verify(context, secret))

def ec_privkey_negate(secret, context=_secp.ctx):
    if len(secret)!=32:
        raise ValueError("Secret should be 32 bytes long")
    _secp.secp256k1_ec_privkey_negate(context, secret);

def ec_pubkey_negate(pubkey, context=_secp.ctx):
    if len(pubkey)!=64:
        raise ValueError("Pubkey should be a 64-byte structure")
    r = _secp.secp256k1_ec_pubkey_negate(context, pubkey)
    if r == 0:
        raise ValueError("Failed to negate pubkey")

def ec_privkey_tweak_add(secret, tweak, context=_secp.ctx):
    if len(secret)!=32 or len(tweak)!=32:
        raise ValueError("Secret and tweak should both be 32 bytes long")
    if _secp.secp256k1_ec_privkey_tweak_add(context, secret, tweak) == 0:
        raise ValueError("Failed to tweak the secret")

def ec_pubkey_tweak_add(pub, tweak, context=_secp.ctx):
    if len(pub)!=64:
        raise ValueError("Public key should be 64 bytes long")
    if len(tweak)!=32:
        raise ValueError("Tweak should be 32 bytes long")
    if _secp.secp256k1_ec_pubkey_tweak_add(context, pub, tweak) == 0:
        raise ValueError("Failed to tweak the public key")

def ec_privkey_add(secret, tweak, context=_secp.ctx):
    if len(secret)!=32 or len(tweak)!=32:
        raise ValueError("Secret and tweak should both be 32 bytes long")
    # ugly copy that works in mpy and py
    s = secret[:1]+secret[1:]
    if _secp.secp256k1_ec_privkey_tweak_add(context, s, tweak) == 0:
        raise ValueError("Failed to tweak the secret")
    return s

def ec_pubkey_add(pub, tweak, context=_secp.ctx):
    if len(pub)!=64:
        raise ValueError("Public key should be 64 bytes long")
    if len(tweak)!=32:
        raise ValueError("Tweak should be 32 bytes long")
    p = pub[:1]+pub[1:]
    if _secp.secp256k1_ec_pubkey_tweak_add(context, p, tweak) == 0:
        raise ValueError("Failed to tweak the public key")
    return p

def ec_privkey_tweak_mul(secret, tweak, context=_secp.ctx):
    if len(secret)!=32 or len(tweak)!=32:
        raise ValueError("Secret and tweak should both be 32 bytes long")
    if _secp.secp256k1_ec_privkey_tweak_mul(context, secret, tweak) == 0:
        raise ValueError("Failed to tweak the secret")

def ec_pubkey_tweak_mul(pub, tweak, context=_secp.ctx):
    if len(pub)!=64:
        raise ValueError("Public key should be 64 bytes long")
    if len(tweak)!=32:
        raise ValueError("Tweak should be 32 bytes long")
    if _secp.secp256k1_ec_pubkey_tweak_mul(context, pub, tweak) == 0:
        raise ValueError("Failed to tweak the public key")

def ec_pubkey_combine(*args, context=_secp.ctx):
    pub = bytes(64)
    pubkeys = (c_char_p * len(args))(*args)
    r = _secp.secp256k1_ec_pubkey_combine(context, pub, pubkeys, len(args))
    if r == 0:
        raise ValueError("Failed to negate pubkey")
    return pub

def ecdsa_sign_recoverable(msg, secret, context=_secp.ctx):
    if len(msg)!=32:
        raise ValueError("Message should be 32 bytes long")
    if len(secret)!=32:
        raise ValueError("Secret key should be 32 bytes long")
    sig = bytes(65)
    r = _secp.secp256k1_ecdsa_sign_recoverable(context, sig, msg, secret, None, None)
    if r == 0:
        raise ValueError("Failed to sign")
    return sig

def ecdsa_recoverable_signature_serialize_compact(sig, context=_secp.ctx):
    if len(sig)!=65:
        raise ValueError("Recoverable signature should be 65 bytes long")
    ser = bytes(64)
    idx = bytes(1)
    r = _secp.secp256k1_ecdsa_recoverable_signature_serialize_compact(context, ser, idx, sig)
    if r == 0:
        raise ValueError("Failed serializing der signature")
    return ser, idx[0]
    
def ecdsa_recoverable_signature_parse_compact(compact_sig, recid, context=_secp.ctx):
    if len(compact_sig)!=64:
        raise ValueError("Signature should be 64 bytes long")
    sig = bytes(65)
    r = _secp.secp256k1_ecdsa_recoverable_signature_parse_compact(context, sig, compact_sig, recid)
    if r == 0:
        raise ValueError("Failed parsing compact signature")
    return sig

def ecdsa_recoverable_signature_convert(sigin, context=_secp.ctx):
    if len(sigin)!=65:
        raise ValueError("Recoverable signature should be 65 bytes long")
    sig = bytes(64)
    r = _secp.secp256k1_ecdsa_recoverable_signature_convert(context, sig, sigin)
    if r == 0:
        raise ValueError("Failed converting signature")
    return sig

def ecdsa_recover(sig, msghash, context=_secp.ctx):
    if len(sig)!=65:
        raise ValueError("Recoverable signature should be 65 bytes long")
    if len(msghash)!=32:
        raise ValueError("Message should be 32 bytes long")
    pub = bytes(64)
    r = _secp.secp256k1_ecdsa_recover(context, pub, sig, msghash)
    if r == 0:
        raise ValueError("Failed to recover public key")
    return pub
