import ctypes, os
import ctypes.util
import platform

from ctypes import (
    cast,
    byref,
    c_char,
    c_byte,
    c_int,
    c_uint,
    c_char_p,
    c_size_t,
    c_void_p,
    c_uint64,
    create_string_buffer,
    CFUNCTYPE,
    POINTER,
)

# Flags to pass to context_create.
CONTEXT_VERIFY = 0b0100000001
CONTEXT_SIGN = 0b1000000001
CONTEXT_NONE = 0b0000000001

# Flags to pass to ec_pubkey_serialize
EC_COMPRESSED = 0b0100000010
EC_UNCOMPRESSED = 0b0000000010


def _find_library():
    library_path = None
    extension = ""
    if platform.system() == "Darwin":
        extension = ".dylib"
    elif platform.system() == "Linux":
        extension = ".so"
    elif platform.system() == "Windows":
        extension = ".dll"

    path = os.path.join(
        os.path.dirname(__file__),
        "prebuilt/libsecp256k1_%s_%s%s"
        % (platform.system().lower(), platform.machine().lower(), extension),
    )
    if os.path.isfile(path):
        return path
    # try searching
    if not library_path:
        library_path = ctypes.util.find_library("libsecp256k1")
    if not library_path:
        library_path = ctypes.util.find_library("secp256k1")
    # library search failed
    if not library_path:
        if platform.system() == "Linux" and os.path.isfile(
            "/usr/local/lib/libsecp256k1.so.0"
        ):
            library_path = "/usr/local/lib/libsecp256k1.so.0"
    return library_path


def _init(flags=(CONTEXT_SIGN | CONTEXT_VERIFY)):
    library_path = _find_library()
    # meh, can't find library
    if not library_path:
        raise RuntimeError(
            "Can't find libsecp256k1 library. Make sure to compile and install it."
        )

    secp256k1 = ctypes.cdll.LoadLibrary(library_path)

    secp256k1.secp256k1_context_create.argtypes = [c_uint]
    secp256k1.secp256k1_context_create.restype = c_void_p

    secp256k1.secp256k1_context_randomize.argtypes = [c_void_p, c_char_p]
    secp256k1.secp256k1_context_randomize.restype = c_int

    secp256k1.secp256k1_ec_seckey_verify.argtypes = [c_void_p, c_char_p]
    secp256k1.secp256k1_ec_seckey_verify.restype = c_int

    secp256k1.secp256k1_ec_privkey_negate.argtypes = [c_void_p, c_char_p]
    secp256k1.secp256k1_ec_privkey_negate.restype = c_int

    secp256k1.secp256k1_ec_pubkey_negate.argtypes = [c_void_p, c_char_p]
    secp256k1.secp256k1_ec_pubkey_negate.restype = c_int

    secp256k1.secp256k1_ec_privkey_tweak_add.argtypes = [c_void_p, c_char_p, c_char_p]
    secp256k1.secp256k1_ec_privkey_tweak_add.restype = c_int

    secp256k1.secp256k1_ec_privkey_tweak_mul.argtypes = [c_void_p, c_char_p, c_char_p]
    secp256k1.secp256k1_ec_privkey_tweak_mul.restype = c_int

    secp256k1.secp256k1_ec_pubkey_create.argtypes = [c_void_p, c_void_p, c_char_p]
    secp256k1.secp256k1_ec_pubkey_create.restype = c_int

    secp256k1.secp256k1_ec_pubkey_parse.argtypes = [c_void_p, c_char_p, c_char_p, c_int]
    secp256k1.secp256k1_ec_pubkey_parse.restype = c_int

    secp256k1.secp256k1_ec_pubkey_serialize.argtypes = [
        c_void_p,
        c_char_p,
        c_void_p,
        c_char_p,
        c_uint,
    ]
    secp256k1.secp256k1_ec_pubkey_serialize.restype = c_int

    secp256k1.secp256k1_ec_pubkey_tweak_add.argtypes = [c_void_p, c_char_p, c_char_p]
    secp256k1.secp256k1_ec_pubkey_tweak_add.restype = c_int

    secp256k1.secp256k1_ec_pubkey_tweak_mul.argtypes = [c_void_p, c_char_p, c_char_p]
    secp256k1.secp256k1_ec_pubkey_tweak_mul.restype = c_int

    secp256k1.secp256k1_ecdsa_signature_parse_compact.argtypes = [
        c_void_p,
        c_char_p,
        c_char_p,
    ]
    secp256k1.secp256k1_ecdsa_signature_parse_compact.restype = c_int

    secp256k1.secp256k1_ecdsa_signature_serialize_compact.argtypes = [
        c_void_p,
        c_char_p,
        c_char_p,
    ]
    secp256k1.secp256k1_ecdsa_signature_serialize_compact.restype = c_int

    secp256k1.secp256k1_ecdsa_signature_parse_der.argtypes = [
        c_void_p,
        c_char_p,
        c_char_p,
        c_uint,
    ]
    secp256k1.secp256k1_ecdsa_signature_parse_der.restype = c_int

    secp256k1.secp256k1_ecdsa_signature_serialize_der.argtypes = [
        c_void_p,
        c_char_p,
        c_void_p,
        c_char_p,
    ]
    secp256k1.secp256k1_ecdsa_signature_serialize_der.restype = c_int

    secp256k1.secp256k1_ecdsa_sign.argtypes = [
        c_void_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_void_p,
        c_char_p,
    ]
    secp256k1.secp256k1_ecdsa_sign.restype = c_int

    secp256k1.secp256k1_ecdsa_verify.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
    secp256k1.secp256k1_ecdsa_verify.restype = c_int

    secp256k1.secp256k1_ec_pubkey_combine.argtypes = [
        c_void_p,
        c_char_p,
        c_void_p,
        c_size_t,
    ]
    secp256k1.secp256k1_ec_pubkey_combine.restype = c_int

    # recoverable module
    try:
        secp256k1.secp256k1_ecdsa_sign_recoverable.argtypes = [
            c_void_p,
            c_char_p,
            c_char_p,
            c_char_p,
            c_void_p,
            c_void_p,
        ]
        secp256k1.secp256k1_ecdsa_sign_recoverable.restype = c_int

        secp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact.argtypes = [
            c_void_p,
            c_char_p,
            c_char_p,
            c_int,
        ]
        secp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact.restype = c_int

        secp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact.argtypes = [
            c_void_p,
            c_char_p,
            c_char_p,
            c_char_p,
        ]
        secp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact.restype = c_int

        secp256k1.secp256k1_ecdsa_recoverable_signature_convert.argtypes = [
            c_void_p,
            c_char_p,
            c_char_p,
        ]
        secp256k1.secp256k1_ecdsa_recoverable_signature_convert.restype = c_int

        secp256k1.secp256k1_ecdsa_recover.argtypes = [
            c_void_p,
            c_char_p,
            c_char_p,
            c_char_p,
        ]
        secp256k1.secp256k1_ecdsa_recover.restype = c_int
    except:
        pass

    # zkp modules
    try:
        # generator module
        secp256k1.secp256k1_generator_parse.argtypes = [c_void_p, c_char_p, c_char_p]
        secp256k1.secp256k1_generator_parse.restype = c_int

        secp256k1.secp256k1_generator_serialize.argtypes = [c_void_p, c_char_p, c_char_p]
        secp256k1.secp256k1_generator_serialize.restype = c_int

        secp256k1.secp256k1_generator_generate.argtypes = [c_void_p, c_char_p, c_char_p]
        secp256k1.secp256k1_generator_generate.restype = c_int

        secp256k1.secp256k1_generator_generate_blinded.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
        secp256k1.secp256k1_generator_generate_blinded.restype = c_int
        
        # pederson commitments
        secp256k1.secp256k1_pedersen_commitment_parse.argtypes = [c_void_p, c_char_p, c_char_p]
        secp256k1.secp256k1_pedersen_commitment_parse.restype = c_int

        secp256k1.secp256k1_pedersen_commitment_serialize.argtypes = [c_void_p, c_char_p, c_char_p]
        secp256k1.secp256k1_pedersen_commitment_serialize.restype = c_int

        secp256k1.secp256k1_pedersen_commit.argtypes = [c_void_p, c_char_p, c_char_p, c_uint64, c_char_p]
        secp256k1.secp256k1_pedersen_commit.restype = c_int

        secp256k1.secp256k1_pedersen_blind_generator_blind_sum.argtypes = [
            c_void_p, # const secp256k1_context* ctx,
            POINTER(c_uint64), # const uint64_t *value,
            c_void_p, # const unsigned char* const* generator_blind,
            c_void_p, # unsigned char* const* blinding_factor,
            c_size_t, # size_t n_total,
            c_size_t, # size_t n_inputs
        ]
        secp256k1.secp256k1_pedersen_blind_generator_blind_sum.restype = c_int

        secp256k1.secp256k1_pedersen_verify_tally.argtypes = [c_void_p, c_void_p, c_size_t, c_void_p, c_size_t]
        secp256k1.secp256k1_pedersen_verify_tally.restype = c_int

        # rangeproof
        secp256k1.secp256k1_rangeproof_rewind.argtypes = [c_void_p, c_char_p, POINTER(c_uint64), c_char_p, POINTER(c_uint64),
                                                          c_char_p, POINTER(c_uint64), POINTER(c_uint64),
                                                          c_char_p, c_char_p, c_uint64,
                                                          c_char_p, c_uint64,
                                                          c_char_p]
        secp256k1.secp256k1_rangeproof_rewind.restype = c_int

        secp256k1.secp256k1_rangeproof_sign.argtypes = [
          c_void_p, # ctx
          c_char_p, # proof
          POINTER(c_uint64), # plen
          c_uint64, # min_value
          c_char_p, # commit
          c_char_p, # blind
          c_char_p, # nonce
          c_int,    # exp
          c_int,    # min_bits
          c_uint64, # value
          c_char_p, # message
          c_uint64, # msg_len
          c_char_p, # extra_commit
          c_uint64, # extra_commit_len
          c_char_p, # gen
        ]
        secp256k1.secp256k1_rangeproof_sign.restype = c_int

        # musig
        secp256k1.secp256k1_xonly_pubkey_from_pubkey.argtypes = [c_void_p, c_char_p, POINTER(c_int), c_char_p]
        secp256k1.secp256k1_xonly_pubkey_from_pubkey.restype = c_int

        secp256k1.secp256k1_musig_pubkey_combine.argtypes = [c_void_p, c_void_p, c_char_p, c_void_p, c_void_p, c_size_t]
        secp256k1.secp256k1_musig_pubkey_combine.restype = c_int

        # surjection proofs
        secp256k1.secp256k1_surjectionproof_initialize.argtypes = [
            c_void_p, # const secp256k1_context* ctx,
            c_char_p, # secp256k1_surjectionproof* proof,
            POINTER(c_size_t), # size_t *input_index,
            c_void_p, # c_char_p, # const secp256k1_fixed_asset_tag* fixed_input_tags,
            c_size_t, # const size_t n_input_tags,
            c_size_t, # const size_t n_input_tags_to_use,
            c_char_p, # const secp256k1_fixed_asset_tag* fixed_output_tag,
            c_size_t, # const size_t n_max_iterations,
            c_char_p, # const unsigned char *random_seed32
        ]
        secp256k1.secp256k1_surjectionproof_initialize.restype = c_int

        secp256k1.secp256k1_surjectionproof_generate.argtypes = [
            c_void_p, # const secp256k1_context* ctx,
            c_char_p, # secp256k1_surjectionproof* proof,
            c_char_p, # const secp256k1_generator* ephemeral_input_tags,
            c_size_t, # size_t n_ephemeral_input_tags,
            c_char_p, # const secp256k1_generator* ephemeral_output_tag,
            c_size_t, # size_t input_index,
            c_char_p, # const unsigned char *input_blinding_key,
            c_char_p, # const unsigned char *output_blinding_key
        ]
        secp256k1.secp256k1_surjectionproof_generate.restype = c_int

        secp256k1.secp256k1_surjectionproof_verify.argtypes = [
            c_void_p, # const secp256k1_context* ctx,
            c_char_p, # const secp256k1_surjectionproof* proof,
            c_char_p, # const secp256k1_generator* ephemeral_input_tags,
            c_size_t, # size_t n_ephemeral_input_tags,
            c_char_p, # const secp256k1_generator* ephemeral_output_tag
        ]
        secp256k1.secp256k1_surjectionproof_verify.restype = c_int

        secp256k1.secp256k1_surjectionproof_serialize.argtypes = [
            c_void_p, # const secp256k1_context* ctx,
            c_char_p, # unsigned char *output,
            POINTER(c_size_t), # size_t *outputlen,
            c_char_p, # const secp256k1_surjectionproof *proof
        ]
        secp256k1.secp256k1_surjectionproof_serialize.restype = c_int

        secp256k1.secp256k1_surjectionproof_serialized_size.argtypes = [
            c_void_p, # const secp256k1_context* ctx,
            c_char_p, # const secp256k1_surjectionproof* proof
        ]
        secp256k1.secp256k1_surjectionproof_serialized_size.restype = c_size_t

        secp256k1.secp256k1_surjectionproof_parse.argtypes = [c_void_p, c_char_p, c_char_p, c_size_t]
        secp256k1.secp256k1_surjectionproof_parse.restype = c_int

    except:
        pass

    secp256k1.ctx = secp256k1.secp256k1_context_create(flags)

    r = secp256k1.secp256k1_context_randomize(secp256k1.ctx, os.urandom(32))

    return secp256k1


_secp = _init()

# bindings equal to ones in micropython
def context_randomize(seed, context=_secp.ctx):
    if len(seed) != 32:
        raise ValueError("Seed should be 32 bytes long")
    if _secp.secp256k1_context_randomize(context, seed) == 0:
        raise RuntimeError("Failed to randomize context")


def ec_pubkey_create(secret, context=_secp.ctx):
    if len(secret) != 32:
        raise ValueError("Private key should be 32 bytes long")
    pub = bytes(64)
    r = _secp.secp256k1_ec_pubkey_create(context, pub, secret)
    if r == 0:
        raise ValueError("Invalid private key")
    return pub


def ec_pubkey_parse(sec, context=_secp.ctx):
    if len(sec) != 33 and len(sec) != 65:
        raise ValueError("Serialized pubkey should be 33 or 65 bytes long")
    if len(sec) == 33:
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
    if len(pubkey) != 64:
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
    if len(compact_sig) != 64:
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
    if len(sig) != 64:
        raise ValueError("Signature should be 64 bytes long")
    der = bytes(78)  # max
    sz = c_size_t(len(der))
    r = _secp.secp256k1_ecdsa_signature_serialize_der(context, der, byref(sz), sig)
    if r == 0:
        raise ValueError("Failed serializing der signature")
    return der[: sz.value]


def ecdsa_signature_serialize_compact(sig, context=_secp.ctx):
    if len(sig) != 64:
        raise ValueError("Signature should be 64 bytes long")
    ser = bytes(64)
    r = _secp.secp256k1_ecdsa_signature_serialize_compact(context, ser, sig)
    if r == 0:
        raise ValueError("Failed serializing der signature")
    return ser


def ecdsa_signature_normalize(sig, context=_secp.ctx):
    if len(sig) != 64:
        raise ValueError("Signature should be 64 bytes long")
    sig2 = bytes(64)
    r = _secp.secp256k1_ecdsa_signature_normalize(context, sig2, sig)
    return sig2


def ecdsa_verify(sig, msg, pub, context=_secp.ctx):
    if len(sig) != 64:
        raise ValueError("Signature should be 64 bytes long")
    if len(msg) != 32:
        raise ValueError("Message should be 32 bytes long")
    if len(pub) != 64:
        raise ValueError("Public key should be 64 bytes long")
    r = _secp.secp256k1_ecdsa_verify(context, sig, msg, pub)
    return bool(r)


def ecdsa_sign(msg, secret, nonce_function=None, extra_data=None, context=_secp.ctx):
    if len(msg) != 32:
        raise ValueError("Message should be 32 bytes long")
    if len(secret) != 32:
        raise ValueError("Secret key should be 32 bytes long")
    if extra_data and len(extra_data) != 32:
        raise ValueError("Extra data should be 32 bytes long")
    sig = bytes(64)
    r = _secp.secp256k1_ecdsa_sign(context, sig, msg, secret, nonce_function, extra_data)
    if r == 0:
        raise ValueError("Failed to sign")
    return sig


def ec_seckey_verify(secret, context=_secp.ctx):
    if len(secret) != 32:
        raise ValueError("Secret should be 32 bytes long")
    return bool(_secp.secp256k1_ec_seckey_verify(context, secret))


def ec_privkey_negate(secret, context=_secp.ctx):
    if len(secret) != 32:
        raise ValueError("Secret should be 32 bytes long")
    b = secret[:1] + secret[1:]
    _secp.secp256k1_ec_privkey_negate(context, b)
    return b


def ec_pubkey_negate(pubkey, context=_secp.ctx):
    if len(pubkey) != 64:
        raise ValueError("Pubkey should be a 64-byte structure")
    pub = pubkey[:1] + pubkey[1:]
    r = _secp.secp256k1_ec_pubkey_negate(context, pub)
    if r == 0:
        raise ValueError("Failed to negate pubkey")
    return pub


def ec_privkey_tweak_add(secret, tweak, context=_secp.ctx):
    if len(secret) != 32 or len(tweak) != 32:
        raise ValueError("Secret and tweak should both be 32 bytes long")
    if _secp.secp256k1_ec_privkey_tweak_add(context, secret, tweak) == 0:
        raise ValueError("Failed to tweak the secret")


def ec_pubkey_tweak_add(pub, tweak, context=_secp.ctx):
    if len(pub) != 64:
        raise ValueError("Public key should be 64 bytes long")
    if len(tweak) != 32:
        raise ValueError("Tweak should be 32 bytes long")
    if _secp.secp256k1_ec_pubkey_tweak_add(context, pub, tweak) == 0:
        raise ValueError("Failed to tweak the public key")


def ec_privkey_add(secret, tweak, context=_secp.ctx):
    if len(secret) != 32 or len(tweak) != 32:
        raise ValueError("Secret and tweak should both be 32 bytes long")
    # ugly copy that works in mpy and py
    s = secret[:1] + secret[1:]
    if _secp.secp256k1_ec_privkey_tweak_add(context, s, tweak) == 0:
        raise ValueError("Failed to tweak the secret")
    return s


def ec_pubkey_add(pub, tweak, context=_secp.ctx):
    if len(pub) != 64:
        raise ValueError("Public key should be 64 bytes long")
    if len(tweak) != 32:
        raise ValueError("Tweak should be 32 bytes long")
    p = pub[:1] + pub[1:]
    if _secp.secp256k1_ec_pubkey_tweak_add(context, p, tweak) == 0:
        raise ValueError("Failed to tweak the public key")
    return p


def ec_privkey_tweak_mul(secret, tweak, context=_secp.ctx):
    if len(secret) != 32 or len(tweak) != 32:
        raise ValueError("Secret and tweak should both be 32 bytes long")
    if _secp.secp256k1_ec_privkey_tweak_mul(context, secret, tweak) == 0:
        raise ValueError("Failed to tweak the secret")


def ec_pubkey_tweak_mul(pub, tweak, context=_secp.ctx):
    if len(pub) != 64:
        raise ValueError("Public key should be 64 bytes long")
    if len(tweak) != 32:
        raise ValueError("Tweak should be 32 bytes long")
    if _secp.secp256k1_ec_pubkey_tweak_mul(context, pub, tweak) == 0:
        raise ValueError("Failed to tweak the public key")


def ec_pubkey_combine(*args, context=_secp.ctx):
    pub = bytes(64)
    pubkeys = (c_char_p * len(args))(*args)
    r = _secp.secp256k1_ec_pubkey_combine(context, pub, pubkeys, len(args))
    if r == 0:
        raise ValueError("Failed to combine pubkeys")
    return pub


def ecdsa_sign_recoverable(msg, secret, context=_secp.ctx):
    if len(msg) != 32:
        raise ValueError("Message should be 32 bytes long")
    if len(secret) != 32:
        raise ValueError("Secret key should be 32 bytes long")
    sig = bytes(65)
    r = _secp.secp256k1_ecdsa_sign_recoverable(context, sig, msg, secret, None, None)
    if r == 0:
        raise ValueError("Failed to sign")
    return sig


def ecdsa_recoverable_signature_serialize_compact(sig, context=_secp.ctx):
    if len(sig) != 65:
        raise ValueError("Recoverable signature should be 65 bytes long")
    ser = bytes(64)
    idx = bytes(1)
    r = _secp.secp256k1_ecdsa_recoverable_signature_serialize_compact(
        context, ser, idx, sig
    )
    if r == 0:
        raise ValueError("Failed serializing der signature")
    return ser, idx[0]


def ecdsa_recoverable_signature_parse_compact(compact_sig, recid, context=_secp.ctx):
    if len(compact_sig) != 64:
        raise ValueError("Signature should be 64 bytes long")
    sig = bytes(65)
    r = _secp.secp256k1_ecdsa_recoverable_signature_parse_compact(
        context, sig, compact_sig, recid
    )
    if r == 0:
        raise ValueError("Failed parsing compact signature")
    return sig


def ecdsa_recoverable_signature_convert(sigin, context=_secp.ctx):
    if len(sigin) != 65:
        raise ValueError("Recoverable signature should be 65 bytes long")
    sig = bytes(64)
    r = _secp.secp256k1_ecdsa_recoverable_signature_convert(context, sig, sigin)
    if r == 0:
        raise ValueError("Failed converting signature")
    return sig


def ecdsa_recover(sig, msghash, context=_secp.ctx):
    if len(sig) != 65:
        raise ValueError("Recoverable signature should be 65 bytes long")
    if len(msghash) != 32:
        raise ValueError("Message should be 32 bytes long")
    pub = bytes(64)
    r = _secp.secp256k1_ecdsa_recover(context, pub, sig, msghash)
    if r == 0:
        raise ValueError("Failed to recover public key")
    return pub

# zkp modules

def pedersen_commitment_parse(inp, context=_secp.ctx):
    if len(inp)!=33:
        raise ValueError("Serialized commitment should be 33 bytes long")
    commit = bytes(64)
    r = _secp.secp256k1_pedersen_commitment_parse(context, commit, inp)
    if r == 0:
        raise ValueError("Failed to parse commitment")
    return commit

def pedersen_commitment_serialize(commit, context=_secp.ctx):
    if len(commit)!=64:
        raise ValueError("Commitment should be 64 bytes long")
    sec = bytes(33)
    r = _secp.secp256k1_pedersen_commitment_serialize(context, sec, commit)
    if r == 0:
        raise ValueError("Failed to serialize commitment")
    return sec

def pedersen_commit(vbf, value, gen, context=_secp.ctx):
    if len(gen)!=64:
        raise ValueError("Generator should be 64 bytes long")
    if len(vbf)!=32:
        raise ValueError(f"Blinding factor should be 32 bytes long, not {len(vbf)}")
    commit = bytes(64)
    r = _secp.secp256k1_pedersen_commit(context, commit, vbf, value, gen)
    if r == 0:
        raise ValueError("Failed to create commitment")
    return commit

def pedersen_blind_generator_blind_sum(values, gens, vbfs, num_inputs, context=_secp.ctx):
    vals = (c_uint64 * len(values))(*values)
    vbf = bytes(vbfs[-1])
    p = c_char_p(vbf) # obtain a pointer of various types
    address = cast(p,c_void_p).value

    vbfs_joined = (c_char_p * len(vbfs))(*vbfs[:-1], address)
    gens_joined = (c_char_p * len(gens))(*gens)
    res = _secp.secp256k1_pedersen_blind_generator_blind_sum(context, vals, gens_joined, vbfs_joined, len(values), num_inputs)
    if res == 0:
        raise ValueError("Failed to get the last blinding factor.")
    res = (c_char * 32).from_address(address).raw
    assert len(res) == 32
    return res

def pedersen_verify_tally(ins, outs, context=_secp.ctx):
    in_ptr = (c_char_p * len(ins))(*ins)
    out_ptr = (c_char_p * len(outs))(*outs)
    res = _secp.secp256k1_pedersen_verify_tally(context, in_ptr, len(in_ptr), out_ptr, len(out_ptr))
    return bool(res)

# generator
def generator_parse(inp, context=_secp.ctx):
    if len(inp)!=33:
        raise ValueError("Serialized generator should be 33 bytes long")
    gen = bytes(64)
    r = _secp.secp256k1_generator_parse(context, gen, inp)
    if r == 0:
        raise ValueError("Failed to parse generator")
    return gen

def generator_generate(asset, context=_secp.ctx):
    if len(asset)!=32:
        raise ValueError("Asset should be 32 bytes long")
    gen = bytes(64)
    r = _secp.secp256k1_generator_generate(context, gen, asset)
    if r == 0:
        raise ValueError("Failed to generate generator")
    return gen

def generator_generate_blinded(asset, abf, context=_secp.ctx):
    if len(asset)!=32:
        raise ValueError("Asset should be 32 bytes long")
    if len(abf)!=32:
        raise ValueError("Asset blinding factor should be 32 bytes long")
    gen = bytes(64)
    r = _secp.secp256k1_generator_generate_blinded(context, gen, asset, abf)
    if r == 0:
        raise ValueError("Failed to generate generator")
    return gen

def generator_serialize(generator, context=_secp.ctx):
    if len(generator)!=64:
        raise ValueError("Generator should be 64 bytes long")
    sec = bytes(33)
    if _secp.secp256k1_generator_serialize(context, sec, generator) == 0:
        raise RuntimeError("Failed to serialize generator")
    return sec

# rangeproof
def rangeproof_rewind(proof, nonce, value_commitment, script_pubkey, generator, message_length=64, context=_secp.ctx):
    if len(generator)!=64:
        raise ValueError("Generator should be 64 bytes long")
    if len(nonce)!=32:
        raise ValueError("Nonce should be 32 bytes long")
    if len(value_commitment)!=64:
        raise ValueError("Value commitment should be 64 bytes long")

    msg = b"\x00"*message_length
    pointer = POINTER(c_uint64)
    msglen = pointer(c_uint64(len(msg)))

    vbf_out = b"\x00"*32
    value_out = pointer(c_uint64(0))
    min_value = pointer(c_uint64(0))
    max_value = pointer(c_uint64(0))
    res = _secp.secp256k1_rangeproof_rewind(context, vbf_out, value_out,
                            msg, msglen,
                            nonce, min_value, max_value,
                            value_commitment, proof, len(proof),
                            script_pubkey, len(script_pubkey),
                            generator)
    if res != 1:
        raise RuntimeError("Failed to rewind the proof")
    return value_out.contents.value, vbf_out, msg[:msglen.contents.value], min_value.contents.value, max_value.contents.value

def rangeproof_sign(nonce, value, value_commitment, vbf, message, extra, gen, min_value=1, exp=0, min_bits=52, context=_secp.ctx):
    if len(gen)!=64:
        raise ValueError("Generator should be 64 bytes long")
    if len(nonce)!=32:
        raise ValueError("Nonce should be 32 bytes long")
    if len(value_commitment)!=64:
        raise ValueError("Value commitment should be 64 bytes long")
    if len(vbf)!=32:
        raise ValueError("Value blinding factor should be 32 bytes long")
    proof = bytes(5134)
    pointer = POINTER(c_uint64)
    prooflen = pointer(c_uint64(len(proof)))
    res = _secp.secp256k1_rangeproof_sign(context, proof, prooflen,
                min_value, value_commitment, vbf, nonce,
                exp, min_bits, value, message, len(message), extra, len(extra), gen)
    if res != 1:
        raise RuntimeError("Failed to generate the proof")
    return bytes(proof[:prooflen.contents.value])

def xonly_pubkey_from_pubkey(pubkey, context=_secp.ctx):
    if len(pubkey)!=64:
        raise ValueError("Pubkey should be 64 bytes long")
    pointer = POINTER(c_int)
    parity = pointer(c_int(0))
    xonly_pub = bytes(64)
    res = _secp.secp256k1_xonly_pubkey_from_pubkey(context, xonly_pub, parity, pubkey)
    if res != 1:
        raise RuntimeError("Failed to convert the pubkey")
    return xonly_pub, bool(parity.contents.value)

def musig_pubkey_combine(*args, context=_secp.ctx):
    pub = bytes(64)
    # TODO: strange that behaviour is different from pubkey_combine...
    pubkeys = b"".join(args) # (c_char_p * len(args))(*args)
    res = _secp.secp256k1_musig_pubkey_combine(context, None, pub, None, pubkeys, len(args))
    if res == 0:
        raise ValueError("Failed to combine pubkeys")
    return pub

# surjection proof
def surjectionproof_initialize(in_tags, out_tag, tags_to_use=None, iterations=100, seed=None, context=_secp.ctx):
    if tags_to_use is None:
        tags_to_use = min(3, len(in_tags))
    if seed is None:
        seed = os.urandom(32)
    proof = bytes(4+8+256//8+32*257)
    pointer = POINTER(c_size_t)
    input_index = pointer(c_size_t(0))
    input_tags = b"".join(in_tags)
    res = _secp.secp256k1_surjectionproof_initialize(context, proof, input_index, input_tags, len(in_tags), tags_to_use, out_tag, iterations, seed)
    if res == 0:
        raise RuntimeError("Failed to initialize the proof")
    return proof, input_index.contents.value

def surjectionproof_generate(proof, in_idx, in_tags, out_tag, in_abf, out_abf, context=_secp.ctx):
    res = _secp.secp256k1_surjectionproof_generate(context, proof, b"".join(in_tags), len(in_tags), out_tag, in_idx, in_abf, out_abf)
    if not res:
        raise RuntimeError("Failed to generate surjection proof")
    return proof

def surjectionproof_verify(proof, in_tags, out_tag, context=_secp.ctx):
    res = _secp.secp256k1_surjectionproof_verify(context, proof, b"".join(in_tags), len(in_tags), out_tag)
    return bool(res)

def surjectionproof_serialize(proof, context=_secp.ctx):
    s = _secp.secp256k1_surjectionproof_serialized_size(context, proof)
    b = bytes(s)
    pointer = POINTER(c_size_t)
    sz = pointer(c_size_t(s))
    _secp.secp256k1_surjectionproof_serialize(context, b, sz, proof)
    if s != sz.contents.value:
        raise RuntimeError("Failed to serialize surjection proof - size mismatch")
    return b

def surjectionproof_parse(proof, context=_secp.ctx):
    parsed_proof = bytes(4+8+256//8+32*257)
    res = _secp.secp256k1_surjectionproof_parse(context, parsed_proof, proof, len(proof))
    if res == 0:
        raise RuntimeError("Failed to parse surjection proof")
    return parsed_proof
