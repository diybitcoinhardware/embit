# ruff: noqa: F403
#
# secp256k1 backend selector.
#
# On MicroPython this re-exports the native ``secp256k1`` module if present.
# On CPython this re-exports ``ctypes_secp256k1`` if libsecp256k1 can be
# loaded. If neither path can resolve the bindings, importing this module
# raises ``Libsecp256k1NotAvailable`` (a subclass of ``ImportError``) with
# a message describing how to install or build the library. This is a hard
# setup-time failure -- a deployment without libsecp256k1 is broken, not a
# soft runtime condition to detect.


class Libsecp256k1NotAvailable(ImportError):
    """Raised at import time when libsecp256k1 bindings cannot be loaded.

    Always raise with ``raise Libsecp256k1NotAvailable() from <underlying>``
    so the underlying loader failure is recorded as the direct cause in
    tracebacks.
    """

    MESSAGE = (
        "libsecp256k1 not found. embit requires libsecp256k1 at import time.\n"
        "\n"
        "On CPython, the recommended way to build it is the Docker "
        "container at docker/ in the embit source tree -- see "
        "docker/README.md. You may also place a prebuilt libsecp256k1 "
        "shared library on your system loader path or at "
        "secp256k1/secp256k1-zkp/.libs/ in the embit source tree.\n"
        "\n"
        "On MicroPython, rebuild the firmware with the secp256k1 native "
        "module enabled."
    )

    def __init__(self, message=None):
        super().__init__(message if message is not None else self.MESSAGE)


try:
    # MicroPython discriminator: this import raises ImportError on CPython.
    # Without it, ``from secp256k1 import *`` could resolve to the repo-local
    # ``secp256k1/`` directory as an implicit namespace package on CPython
    # and silently succeed with an empty namespace.
    from micropython import const  # noqa: F401

    try:
        from secp256k1 import *
    except Exception as _mp_exc:
        raise Libsecp256k1NotAvailable() from _mp_exc
except Libsecp256k1NotAvailable:
    # Re-raise so the outer ImportError clause below doesn't swallow it.
    raise
except ImportError:
    # CPython branch: ``from micropython import const`` raised ImportError,
    # confirming we're not on MicroPython. Only catch ImportError here so
    # unrelated runtime errors from a MicroPython environment surface as
    # themselves instead of being misrouted to the CPython loader.
    try:
        from . import ctypes_secp256k1 as _ctypes_secp256k1
        from .ctypes_secp256k1 import *
    except Exception as _cp_exc:
        raise Libsecp256k1NotAvailable() from _cp_exc

    _secp = _ctypes_secp256k1._secp

    # Optional libsecp modules (ECDH, Schnorr, recovery, ZKP) may or may not be
    # present in the loaded library. With the secp256k1-zkp fork all are
    # present; if a future build targets upstream secp256k1 without certain
    # modules, we drop the corresponding wrapper from globals() so that
    # capability-dependent tests can skip via ``hasattr(secp256k1, name)``.

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
        if _name in globals():
            del globals()[_name]
