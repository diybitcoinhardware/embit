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


# BIP-341 nothing-up-my-sleeve (NUMS) internal key. A taproot output that
# commits to H as its internal key is script-path-only and is NOT eligible for
# silent-payment shared-secret derivation (BIP-352).
NUMS_H = bytes.fromhex(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)


def witness_version(script):
    """Return the segwit witness version (0-16) of a witness program script,
    or None when the script is not a canonical witness program."""
    data = script.data
    if len(data) < 4 or len(data) > 42:
        return None
    op = data[0]
    if op == 0x00:
        version = 0
    elif 0x51 <= op <= 0x60:  # OP_1 .. OP_16
        version = op - 0x50
    else:
        return None
    # second byte must be a direct push of the remaining (2..40) program bytes
    if data[1] != len(data) - 2 or not (2 <= data[1] <= 40):
        return None
    return version


def get_eligible_inputs(inputs, has_sp_outputs: bool = False):
    """
    Get list of eligible input indices for SP computation.

    Per BIP-352 the eligible input types are P2PKH, P2WPKH, P2SH-P2WPKH and
    P2TR (taproot, segwit v1).  Taproot inputs committing to the NUMS internal
    key are excluded (script-path-only, no usable key for ECDH).

    Per BIP-375, when there are SP outputs an input spending a Segwit version
    > 1 output is forbidden and the Signer must fail.

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

        # BIP-375: refuse to sign when an input spends a Segwit v>1 output.
        if has_sp_outputs:
            wv = witness_version(script)
            if wv is not None and wv > 1:
                raise SPValidationError(
                    "Input {} spends a Segwit version > 1 output with SP "
                    "outputs".format(i)
                )

        if script_type == "p2tr":
            # NUMS internal key -> script-path-only, not eligible.
            if (
                inp.taproot_internal_key is not None
                and inp.taproot_internal_key.xonly() == NUMS_H
            ):
                continue
            eligible.append(i)
        elif script_type in {"p2pkh", "p2wpkh"}:
            eligible.append(i)
        elif script_type == "p2sh":
            # Only P2SH-P2WPKH is eligible.
            if inp.redeem_script and inp.redeem_script.script_type() == "p2wpkh":
                eligible.append(i)

    return eligible
