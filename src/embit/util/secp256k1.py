# ruff: noqa: F403, E722
try:
    # if it's micropython
    # `from micropython import const` is the discriminator: it raises ImportError on
    # CPython, forcing the fallback branch. Without it, `from secp256k1 import *`
    # can resolve to the repo-local `secp256k1/` libsecp256k1 build directory as an
    # implicit namespace package and silently succeed with an empty namespace.
    from micropython import const  # noqa: F401
    from secp256k1 import *
except:
    # we are in python
    try:
        # try ctypes bindings
        from . import ctypes_secp256k1 as _ctypes_secp256k1
        from .ctypes_secp256k1 import *
        _secp = _ctypes_secp256k1._secp

        # For optional modules (ECDH/Schnorr/recovery/ZKP), keep ctypes when symbols
        # are exported by the loaded library, otherwise use pure-Python fallbacks when
        # available or hide the API so tests can skip capability-dependent paths.
        from . import py_secp256k1 as _py_secp256k1

        def _has_ctypes_symbol(symbol_name):
            try:
                getattr(_secp, symbol_name)
                return True
            except AttributeError:
                return False

        _OPTIONAL_SYMBOLS = {
            "ecdh": "secp256k1_ecdh",
            "xonly_pubkey_from_pubkey": "secp256k1_xonly_pubkey_from_pubkey",
            "schnorrsig_verify": "secp256k1_schnorrsig_verify",
            "schnorrsig_sign": "secp256k1_schnorrsig_sign",
            "keypair_create": "secp256k1_keypair_create",
            "ecdsa_sign_recoverable": "secp256k1_ecdsa_sign_recoverable",
            "ecdsa_recoverable_signature_parse_compact": (
                "secp256k1_ecdsa_recoverable_signature_parse_compact"
            ),
            "ecdsa_recoverable_signature_serialize_compact": (
                "secp256k1_ecdsa_recoverable_signature_serialize_compact"
            ),
            "ecdsa_recoverable_signature_convert": (
                "secp256k1_ecdsa_recoverable_signature_convert"
            ),
            "ecdsa_recover": "secp256k1_ecdsa_recover",
            "generator_parse": "secp256k1_generator_parse",
            "generator_generate": "secp256k1_generator_generate",
            "generator_generate_blinded": "secp256k1_generator_generate_blinded",
            "generator_serialize": "secp256k1_generator_serialize",
            "pedersen_commitment_parse": "secp256k1_pedersen_commitment_parse",
            "pedersen_commitment_serialize": "secp256k1_pedersen_commitment_serialize",
            "pedersen_commit": "secp256k1_pedersen_commit",
            "pedersen_blind_generator_blind_sum": (
                "secp256k1_pedersen_blind_generator_blind_sum"
            ),
            "pedersen_verify_tally": "secp256k1_pedersen_verify_tally",
            "rangeproof_rewind": "secp256k1_rangeproof_rewind",
            "rangeproof_verify": "secp256k1_rangeproof_verify",
            "rangeproof_sign": "secp256k1_rangeproof_sign",
            "surjectionproof_initialize": "secp256k1_surjectionproof_initialize",
            "surjectionproof_generate": "secp256k1_surjectionproof_generate",
            "surjectionproof_verify": "secp256k1_surjectionproof_verify",
            "surjectionproof_serialize": "secp256k1_surjectionproof_serialize",
            "surjectionproof_parse": "secp256k1_surjectionproof_parse",
        }
        for _name, _symbol in _OPTIONAL_SYMBOLS.items():
            if _has_ctypes_symbol(_symbol):
                continue
            if hasattr(_py_secp256k1, _name):
                globals()[_name] = getattr(_py_secp256k1, _name)
            elif _name in globals():
                del globals()[_name]
    except:
        # fallback to python version
        from .py_secp256k1 import *
