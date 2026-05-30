"""
BIP-375 ECDH share and DLEQ proof computation, plus input eligibility.
"""

import os

from .. import ec
from . import dleq
from ..util.key import SECP256K1_ORDER
from ..util.secp256k1 import (
    ec_pubkey_parse,
    ec_pubkey_serialize,
    ec_pubkey_tweak_mul,
    EC_COMPRESSED,
    ec_seckey_verify,
)
from .fields import SPFieldError, SPValidationError


def compute_ecdh_share(private_key: bytes, scan_key: ec.PublicKey) -> bytes:
    """
    Compute ECDH share for a single private key.

    Args:
        private_key: 32-byte private key
        scan_key: The scan key to compute share with

    Returns:
        33-byte ECDH share (a·B_scan) compressed
    """
    if len(private_key) != 32:
        raise SPFieldError("Private key must be 32 bytes")

    # Compute a·B_scan
    b_internal = bytearray(ec_pubkey_parse(scan_key.sec()))
    ec_pubkey_tweak_mul(b_internal, private_key)
    return ec_pubkey_serialize(b_internal, EC_COMPRESSED)


def compute_global_ecdh_share(private_keys, scan_key: ec.PublicKey):
    """
    Compute global ECDH share from multiple private keys.

    Args:
        private_keys: List of 32-byte private keys (all eligible inputs)
        scan_key: The scan key to compute share with

    Returns:
        33-byte ECDH share (a_sum·B_scan) compressed, or None if a_sum=0
    """
    if not private_keys:
        return None

    # Verify all private keys
    for priv in private_keys:
        if not ec_seckey_verify(priv):
            raise SPFieldError("Invalid private key")

    # Sum all private keys mod n
    a_sum = sum(int.from_bytes(priv, "big") for priv in private_keys) % SECP256K1_ORDER
    if a_sum == 0:
        return None

    a_sum_bytes = a_sum.to_bytes(32, "big")

    # Compute a_sum·B_scan
    b_internal = bytearray(ec_pubkey_parse(scan_key.sec()))
    ec_pubkey_tweak_mul(b_internal, a_sum_bytes)
    return ec_pubkey_serialize(b_internal, EC_COMPRESSED)


def compute_dleq_proof(
    private_key: bytes,
    scan_key: ec.PublicKey,
    ecdh_share: bytes,
    aux_rand=None,
) -> bytes:
    """
    Generate DLEQ proof for an input's ECDH share.

    Args:
        private_key: 32-byte private key (a)
        scan_key: The scan key (B_scan)
        ecdh_share: The ECDH share (a·B_scan) - used for self-verification
        aux_rand: 32-byte auxiliary randomness. When None, fresh bytes are
                  generated via os.urandom; pass explicit bytes for
                  deterministic behaviour or hardware wallet use.

    Returns:
        64-byte DLEQ proof
    """
    r = aux_rand if aux_rand is not None else os.urandom(32)
    try:
        return dleq.generate_dleq_proof(private_key, scan_key.sec(), r=r)
    except dleq.DLEQError as e:
        raise SPFieldError("Failed to generate DLEQ proof: {}".format(e))


def compute_global_dleq_proof(
    private_keys,
    scan_key: ec.PublicKey,
    global_share: bytes,
    aux_rand=None,
) -> bytes:
    """
    Generate DLEQ proof for global ECDH share.

    Args:
        private_keys: List of 32-byte private keys (all eligible inputs)
        scan_key: The scan key (B_scan)
        global_share: The global ECDH share (a_sum·B_scan)
        aux_rand: 32-byte auxiliary randomness. When None, fresh bytes are
                  generated via os.urandom.

    Returns:
        64-byte DLEQ proof
    """
    # Sum all private keys mod n
    a_sum = sum(int.from_bytes(priv, "big") for priv in private_keys) % SECP256K1_ORDER
    if a_sum == 0:
        raise SPFieldError("Cannot generate proof for zero sum")

    a_sum_bytes = a_sum.to_bytes(32, "big")
    r = aux_rand if aux_rand is not None else os.urandom(32)

    try:
        return dleq.generate_dleq_proof(a_sum_bytes, scan_key.sec(), r=r)
    except dleq.DLEQError as e:
        raise SPFieldError("Failed to generate global DLEQ proof: {}".format(e))


def pubkey_hash_from_script(script, redeem_script=None):
    """Return the 20-byte HASH160(pubkey) committed by a single-key script.

    Handles the SP-eligible script types (P2WPKH, P2PKH, P2SH-P2WPKH); returns
    None for any other type. This is the single source of truth for matching a
    pubkey to an input script, used by both the signer and the validator.
    """
    if script is None:
        return None
    script_type = script.script_type()
    if script_type == "p2wpkh":
        return bytes(script.data[2:22])
    if script_type == "p2pkh":
        return bytes(script.data[3:23])
    if (
        script_type == "p2sh"
        and redeem_script is not None
        and redeem_script.script_type() == "p2wpkh"
    ):
        return bytes(redeem_script.data[2:22])
    return None


def get_eligible_inputs(inputs, has_sp_outputs: bool = False):
    """
    Get list of eligible input indices for SP computation.

    An input is eligible if:
    1. Its previous output is P2WPKH, P2PKH, or P2SH-P2WPKH
    2. When SP outputs are present, no Segwit version > 1 inputs are allowed

    Args:
        inputs: List of PSBT input scopes
        has_sp_outputs: Whether the PSBT has any SP outputs

    Returns:
        List of eligible input indices
    """
    eligible = []

    for i, inp in enumerate(inputs):
        script = inp.script_pubkey
        if script is None:
            continue

        script_type = script.script_type()

        # With SP outputs, reject Segwit v>1
        if has_sp_outputs and script_type == "p2tr":
            raise SPValidationError(
                "Input {} uses Segwit version > 1 (P2TR) with SP outputs".format(i)
            )

        # Eligible: P2PKH, P2WPKH, P2SH-P2WPKH
        if script_type in {"p2pkh", "p2wpkh", "p2sh"}:
            # For P2SH, check if it wraps P2WPKH
            if script_type == "p2sh" and inp.redeem_script:
                redeem_type = inp.redeem_script.script_type()
                if redeem_type == "p2wpkh":
                    # For P2SH-wrapped, we need the public key from redeem script
                    eligible.append(i)
            elif script_type != "p2sh":
                eligible.append(i)

    return eligible
