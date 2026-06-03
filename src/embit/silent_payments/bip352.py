"""
BIP-352: Silent Payments
see: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki
"""

from .. import bech32, ec
from ..util import secp256k1
from ..hashes import tagged_hash
from ..util.key import SECP256K1_ORDER
from ..util.secp256k1 import (
    ec_pubkey_create,
    ec_pubkey_serialize,
    ec_pubkey_parse,
    ec_pubkey_tweak_mul,
    ec_pubkey_tweak_add,
    ec_seckey_verify,
    ec_privkey_negate,
    EC_COMPRESSED,
)
from binascii import hexlify


def generate_silent_payment_address(
    scan_privkey: ec.PrivateKey,
    spend_pubkey: ec.PublicKey,
    label=None,
    network: str = "main",
    version: int = 0,
) -> str:
    """
    Adapted from https://github.com/bitcoin/bips/blob/master/bip-0352/reference.py

    Generates the recipient's reusable silent payment address for a given:
        * scan private key
        * spend public key
        * optional label for labeled addresses. It must be a 32-bit unsigned
          integer `m`; `m = 0` is reserved for change and cannot be used here.
    """
    scan_pubkey = scan_privkey.get_public_key()
    if label is not None:
        # Labels are 32-bit unsigned ints; m = 0 is reserved for change. See
        # https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki#address-encoding
        if not isinstance(label, int) or isinstance(label, bool):
            raise TypeError("Label must be an int.")
        if not 1 <= label <= 0xFFFFFFFF:
            raise ValueError(
                "Label must be a 32-bit unsigned integer in [1, 2**32 - 1]."
            )
        label_bytes = label.to_bytes(4, "big")
        tweak = tagged_hash("BIP0352/Label", scan_privkey.secret + label_bytes)
        spend_pubkey = ec.PublicKey(
            secp256k1.ec_pubkey_add(
                secp256k1.ec_pubkey_parse(spend_pubkey.sec()), tweak
            )
        )

    data = bech32.convertbits(scan_pubkey.sec() + spend_pubkey.sec(), 8, 5)
    hrp = "sp" if network == "main" else "tsp"
    return bech32.bech32_encode(bech32.Encoding.BECH32M, hrp, [version] + data)


# TODO: use the bech32 decode function once the flexible bech32 PR is in
def decode_silent_payment_address(address: str):
    """
    Decode a silent payment address and return the scan and spend public keys.
    """
    if address.startswith("sp1"):
        hrp = "sp"
    elif address.startswith("tsp1"):
        hrp = "tsp"
    else:
        raise ValueError("Invalid silent payment address: unknown HRP")

    try:
        encoding, hrpgot, data = bech32.bech32_decode(address)
    except bech32.Bech32DecodeError as e:
        raise ValueError("Invalid silent payment address: {}".format(e))

    if hrpgot != hrp:
        raise ValueError("Invalid silent payment address: HRP mismatch")

    if encoding != bech32.Encoding.BECH32M:
        raise ValueError("Invalid silent payment address: must use bech32m encoding")

    if data[0] != 0:
        raise ValueError(
            "Invalid silent payment address: unsupported version {}".format(data[0])
        )

    try:
        decoded = bech32.convertbits(data[1:], 5, 8, False)
    except bech32.Bech32DecodeError:
        raise ValueError("Invalid silent payment address: conversion failed")

    try:
        B_scan = ec.PublicKey.parse(bytes(decoded[:33]))
        B_spend = ec.PublicKey.parse(bytes(decoded[33:]))
    except Exception as e:
        raise ValueError(
            "Invalid silent payment address: invalid public keys - {}".format(e)
        )

    return B_scan, B_spend


def get_input_hash(outpoints, sum_pubkey_bytes: bytes) -> bytes:
    lowest_outpoint = sorted(outpoints, key=lambda o: o.serialize())[0]
    preimage = lowest_outpoint.serialize() + sum_pubkey_bytes
    return tagged_hash("BIP0352/Inputs", preimage)


def create_outputs(input_privkeys, outpoints, recipients):
    """
    Creates silent payment outputs for given recipients.

    Args:
        input_privkeys: List of (private_key_bytes, is_xonly) tuples
        outpoints: List of transaction outpoints
        recipients: List of silent payment addresses (strings) - duplicates are allowed

    Returns:
        Dictionary mapping each unique recipient address to list of output hex strings
    """
    if not input_privkeys:
        return {}

    a_sum = 0
    for sec, is_xonly in input_privkeys:
        if not ec_seckey_verify(sec):
            raise ValueError("Invalid private key")
        if is_xonly:
            pub = ec_pubkey_create(sec)
            ser = ec_pubkey_serialize(pub)
            if ser[0] == 0x03:
                sec = ec_privkey_negate(sec)
        a_sum = (a_sum + int.from_bytes(sec, "big")) % SECP256K1_ORDER

    if a_sum == 0:
        return {}

    a_sum_bytes = a_sum.to_bytes(32, "big")
    A = ec_pubkey_create(a_sum_bytes)

    input_hash = get_input_hash(outpoints, ec_pubkey_serialize(A))

    recipient_counts = {}
    for addr in recipients:
        recipient_counts[addr] = recipient_counts.get(addr, 0) + 1

    groups = {}
    for addr, count in recipient_counts.items():
        B_scan, B_spend = decode_silent_payment_address(addr)
        groups.setdefault(B_scan, []).append((B_spend, addr, count))

    result = {addr: [] for addr in recipient_counts.keys()}
    scalar = (int.from_bytes(input_hash, "big") * a_sum) % SECP256K1_ORDER
    scalar_bytes = scalar.to_bytes(32, "big")

    for B_scan, B_spend_list in groups.items():
        # bytearray: tweak_* mutate the point in place (required by the pure-Python
        # secp256k1 backend, and works with the ctypes one too)
        ecdh_point = bytearray(ec_pubkey_parse(B_scan.sec()))
        ec_pubkey_tweak_mul(ecdh_point, scalar_bytes)
        xonly_shared_secret = ec_pubkey_serialize(ecdh_point)

        k = 0
        for B_spend, addr, count in B_spend_list:
            for _ in range(count):
                t_k = tagged_hash(
                    "BIP0352/SharedSecret",
                    xonly_shared_secret + k.to_bytes(4, "big"),
                )

                P_k = bytearray(ec_pubkey_parse(B_spend.sec()))
                ec_pubkey_tweak_add(P_k, t_k)

                xonly = ec_pubkey_serialize(P_k)[1:33]
                result[addr].append(hexlify(xonly).decode())
                k += 1

    return result


def derive_silent_payment_outputs(ecdh_share, recipients):
    """
    Derive silent payment outputs for recipients from a precomputed ECDH share.

    Unlike create_outputs (which derives the share from input private keys),
    this takes the ECDH shared-secret point directly, as used by the BIP-375
    PSBT flow where shares are carried in the PSBT.

    The spend key of each recipient is the final per-output spend key as carried
    in PSBT_OUT_SP_V0_INFO (already label-tweaked when the address was labeled),
    so no label tweak is applied here. ``k`` is the recipient's position in
    ``recipients`` (the caller fixes the ordering).

    Args:
        ecdh_share: 33-byte compressed shared-secret point, already multiplied
            by input_hash (validator does this before calling).
        recipients: ordered list of (scan_key, spend_key, label) tuples; label
            is informational and unused here.

    Returns:
        Dict mapping recipient position k to output pubkey x-only (32 bytes).
    """
    if not recipients:
        return {}

    result = {}

    for k, (scan_key, spend_key, _label) in enumerate(recipients):
        t_k = tagged_hash(
            "BIP0352/SharedSecret",
            ecdh_share + k.to_bytes(4, "big"),
        )

        # P_k = B_spend + t_k·G
        p_k_internal = bytearray(ec_pubkey_parse(spend_key.sec()))
        ec_pubkey_tweak_add(p_k_internal, t_k)
        p_k = ec_pubkey_serialize(p_k_internal, EC_COMPRESSED)

        # Store as p2tr output (extract xonly)
        result[k] = p_k[1:33]

    return result
