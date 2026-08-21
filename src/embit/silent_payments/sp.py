"""
BIP-352: Silent Payments — core cryptography, address encoding, output
derivation, and PSBT input/output helpers.

see: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki
"""

from .. import bech32, ec
from ..hashes import tagged_hash
from ..script import p2sh
from ..util.key import SECP256K1_ORDER
from ..util.secp256k1 import (
    ec_pubkey_add,
    ec_pubkey_serialize,
    ec_pubkey_parse,
    ec_pubkey_tweak_add,
    ec_pubkey_create,
    ec_pubkey_tweak_mul,
    EC_COMPRESSED,
)
from ..base import EmbitError


class SPFieldError(EmbitError):
    pass


class SPValidationError(EmbitError):
    pass


# BIP-352 Sending: max number of outputs per scan key.
K_MAX = 2323
_NUMS_XONLY = ec.NUMS_PUBKEY.xonly()


def _tweak_mul(point_sec, scalar):
    """Multiply a compressed point by a scalar, returning the compressed result."""
    point = bytearray(ec_pubkey_parse(point_sec))
    ec_pubkey_tweak_mul(point, scalar)
    return ec_pubkey_serialize(point, EC_COMPRESSED)


def _validate_label(m, allow_zero=True):
    """Validate a BIP-352 label index."""
    if not isinstance(m, int) or isinstance(m, bool):
        raise TypeError("Label must be an int.")
    lo = 0 if allow_zero else 1
    if not lo <= m <= 0xFFFFFFFF:
        raise SPValidationError(
            "Label must be a 32-bit unsigned integer in [{}, 2**32 - 1].".format(lo)
        )


def apply_label(spend_pubkey, scan_privkey, m):
    """BIP-352 label tweak:
    B_m = B_spend + tagged_hash("BIP0352/Label", scan_priv || ser32(m))·G"""
    _validate_label(m, allow_zero=True)
    tweak = tagged_hash("BIP0352/Label", scan_privkey.secret + m.to_bytes(4, "big"))
    return ec.PublicKey(ec_pubkey_add(ec_pubkey_parse(spend_pubkey.sec()), tweak))


def encode_silent_payment_address(scan_pubkey, spend_pubkey, network="main", version=0):
    """Bech32m-encode a BIP-352 Silent Payment address from its scan/spend
    public keys."""
    # bech32_encode indexes CHARSET with the version, so an out-of-range one is
    # not an error there: 32 raises IndexError and -1 wraps to 31, silently
    # emitting an address whose checksum covers a value no decoder can read.
    if not 0 <= version <= 30:
        raise SPValidationError(
            "Silent payment address version must be in [0, 30], got {}".format(version)
        )
    data = bech32.convertbits(scan_pubkey.sec() + spend_pubkey.sec(), 8, 5)
    hrp = "sp" if network == "main" else "tsp"
    return bech32.bech32_encode(bech32.Encoding.BECH32M, hrp, [version] + data)


def generate_silent_payment_address(
    scan_privkey, spend_pubkey, label=None, network="main", version=0
):
    """Generates the recipient's reusable silent payment address."""
    scan_pubkey = scan_privkey.get_public_key()
    if label is not None:
        _validate_label(label, allow_zero=False)
        spend_pubkey = apply_label(spend_pubkey, scan_privkey, label)
    return encode_silent_payment_address(
        scan_pubkey, spend_pubkey, network=network, version=version
    )


def decode_silent_payment_address(address):
    """Decode a silent payment address and return the (scan, spend) public keys."""
    try:
        encoding, hrpgot, data = bech32.bech32_decode(address)
    except bech32.Bech32DecodeError as e:
        raise SPValidationError("Invalid silent payment address: {}".format(e))
    if hrpgot not in ("sp", "tsp"):
        raise SPValidationError("Invalid silent payment address: unknown HRP")
    if encoding != bech32.Encoding.BECH32M:
        raise SPValidationError(
            "Invalid silent payment address: must use bech32m encoding"
        )
    if not data:
        raise SPValidationError("Invalid silent payment address: missing version")
    version = data[0]
    # BIP-352 forward compatibility: version 31 is reserved and must be
    # rejected; versions 1-30 keep the first 66 bytes and ignore any trailing
    # data; version 0 must be exactly 66 bytes.
    if version == 31:
        raise SPValidationError(
            "Invalid silent payment address: version 31 is reserved"
        )
    try:
        decoded = bytes(bech32.convertbits(data[1:], 5, 8, False))
    except bech32.Bech32DecodeError:
        raise SPValidationError("Invalid silent payment address: conversion failed")

    if version == 0 and len(decoded) != 66:
        raise SPValidationError(
            "Invalid silent payment address: version 0 payload must be 66 "
            "bytes, got {}".format(len(decoded))
        )
    if len(decoded) < 66:
        raise SPValidationError(
            "Invalid silent payment address: payload must be at least 66 bytes"
        )

    try:
        return (
            ec.PublicKey.parse(decoded[:33]),
            ec.PublicKey.parse(decoded[33:66]),
        )
    except EmbitError as e:
        raise SPValidationError("Invalid silent payment address: {}".format(e))


def _serialize_outpoint(o):
    return bytes(reversed(o.txid)) + o.vout.to_bytes(4, "little")


def get_input_hash(outpoints, A_sum):
    """BIP-352 input_hash: tagged_hash("BIP0352/Inputs", lowest_outpoint || A)."""
    if not outpoints:
        raise SPValidationError("get_input_hash requires at least one outpoint")
    serialized = [_serialize_outpoint(o) for o in outpoints]
    lowest = min(serialized)
    return tagged_hash("BIP0352/Inputs", lowest + A_sum)


def derive_recipient_outputs(shared_secret, spend_keys):
    """Derive silent payment x-only outputs (one per spend key, in k order)."""
    if not spend_keys:
        return []
    if len(spend_keys) > K_MAX:
        raise SPValidationError(
            "Too many outputs for one scan key: {} > {}".format(len(spend_keys), K_MAX)
        )
    result = []
    for k, spend_key in enumerate(spend_keys):
        t_k = tagged_hash("BIP0352/SharedSecret", shared_secret + k.to_bytes(4, "big"))
        p_k = bytearray(ec_pubkey_parse(spend_key.sec()))
        ec_pubkey_tweak_add(p_k, t_k)
        result.append(ec_pubkey_serialize(p_k, EC_COMPRESSED)[1:])
    return result


def derive_sp_outputs(priv_keys, outpoints, scan_spend_groups):
    """Core output derivation verified against BIP-352 test vectors.

    Args:
        priv_keys: List of 32-byte normalized private key scalars (single-signer).
        outpoints: Objects with .txid/.vout (e.g. TransactionInput).
        scan_spend_groups: {scan_key_bytes: (scan_key, [spend_key, ...])}.

    Returns:
        (a_sum_bytes, A_sum_sec, {scan_key_bytes: (ecdh_share, outputs)}), or
        None when the private keys sum to zero (no shared secret can be
        derived). A_sum_sec is returned so callers that need the public sum -
        DLEQ verification, for one - don't derive it a second time.
    """
    a_sum = sum(int.from_bytes(priv, "big") for priv in priv_keys) % SECP256K1_ORDER
    if a_sum == 0:
        return None
    a_sum_bytes = a_sum.to_bytes(32, "big")
    A_sum_sec = ec_pubkey_serialize(ec_pubkey_create(a_sum_bytes))

    input_hash = get_input_hash(outpoints, A_sum_sec)

    results = {}
    for sk_bytes, (scan_key, spend_keys) in scan_spend_groups.items():
        ecdh_share = _tweak_mul(scan_key.sec(), a_sum_bytes)

        outputs = derive_recipient_outputs(
            _tweak_mul(ecdh_share, input_hash), spend_keys
        )
        results[sk_bytes] = (ecdh_share, outputs)

    return a_sum_bytes, A_sum_sec, results


def pubkey_hash_from_script(script, redeem_script=None):
    """Return the 20-byte HASH160(pubkey) committed by a single-key script.
    Handles P2WPKH, P2PKH, P2SH-P2WPKH; returns None for others."""
    if script is None:
        return None
    stype = script.script_type()
    if stype == "p2wpkh":
        return bytes(script.data[2:22])
    if stype == "p2pkh":
        return bytes(script.data[3:23])
    if (
        stype == "p2sh"
        and redeem_script
        and redeem_script.script_type() == "p2wpkh"
        and p2sh(redeem_script) == script
    ):
        return bytes(redeem_script.data[2:22])
    return None


def witness_version(script):
    """Return the segwit witness version (0-16), or None if not a witness program."""
    data = script.data
    if len(data) < 4 or len(data) > 42:
        return None
    op = data[0]
    if op == 0x00:
        ver = 0
    elif 0x51 <= op <= 0x60:
        ver = op - 0x50
    else:
        return None
    return ver if data[1] == len(data) - 2 and 2 <= data[1] <= 40 else None


def _p2sh_redeem_script(inp, i):
    """Return a P2SH input's redeem script, proven against its UTXO.

    PSBT fields are unauthenticated; only the scriptPubKey comes from the UTXO,
    so a redeem script is trusted only once it hashes to it. Anything that
    cannot be proven aborts rather than defaulting to ineligible: an input
    wrongly included in - or excluded from - a_sum changes the shared secret
    for every SP output in the transaction.
    """
    redeem = inp.redeem_script
    if redeem is None:
        raise SPValidationError(
            "Input {} is P2SH with no redeem script; SP eligibility is "
            "undetermined for every output in this transaction".format(i)
        )
    if p2sh(redeem) != inp.script_pubkey:
        raise SPValidationError(
            "Input {} declares a redeem script that does not hash to its "
            "scriptPubKey".format(i)
        )
    return redeem


def _proves_nums_commitment(inp, script):
    """Whether this P2TR input provably commits to H as its internal key.

    BIP-352 makes H the single exception to "the sending wallet MUST have
    access to the private key corresponding to the taproot output key", so it
    is the one claim that may drop an input from a_sum. PSBT fields are
    unauthenticated, so it counts only once it reproduces the scriptPubKey,
    which is all the UTXO vouches for.
    """
    internal = inp.taproot_internal_key
    if internal is None or internal.xonly() != _NUMS_XONLY:
        return False
    output_xonly = bytes(script.data[2:34])
    if internal.xonly() == output_xonly:
        return True
    try:
        merkle_root = inp.taproot_merkle_root or b""
        return internal.taproot_tweak(merkle_root).xonly() == output_xonly
    except EmbitError:
        return False


def get_eligible_inputs(inputs):
    """Get list of eligible input indices for SP computation.
    Per BIP-352: P2PKH, P2WPKH, P2SH-P2WPKH, P2TR.
    (The BIP-375 Segwit v>1 rule is enforced by SilentPaymentsPSBT.validate_sp.)"""
    eligible = []
    for i, inp in enumerate(inputs):
        script = inp.script_pubkey
        if script is None:
            raise SPValidationError(
                "Input {} has no UTXO; cannot determine SP eligibility".format(i)
            )
        stype = script.script_type()
        if stype in ("p2pkh", "p2wpkh"):
            eligible.append(i)
        elif stype == "p2sh":
            if _p2sh_redeem_script(inp, i).script_type() == "p2wpkh":
                eligible.append(i)
        elif stype == "p2tr":
            # BIP-352: "For each taproot output spent the sending wallet MUST
            # have access to the private key corresponding to the taproot
            # output key, unless H is used as the internal public key." H is
            # the only exception, so everything else stays eligible and
            # _resolve_sp_privkeys decides. BIP-341 recommends tweaking H by a
            # random r to hide it; such an input is simply unspendable here,
            # and aborting there is the correct outcome - the transaction
            # cannot be a silent payment at all.
            #
            # An unproven H claim stays eligible too, and that is what makes it
            # safe. Excluding an input on the PSBT's say-so is silent: it never
            # reaches _resolve_sp_privkeys to be missed, yet the signer still
            # key-path signs it, so the recipient - who scores eligibility from
            # the on-chain witness - derives a shared secret we never used and
            # never finds the payment. Kept eligible, a false claim about an
            # input we control resolves normally, and a true one has no key to
            # resolve and aborts the send.
            if not _proves_nums_commitment(inp, script):
                eligible.append(i)
    return eligible


def group_sp_outputs_by_scan_key(outputs):
    """Group SP outputs by scan key, ordered by spend key then output index
    (BIP-375 k ordering).
    Returns ({scan_key_bytes: (scan_key, [spend_key, ...])},
             {scan_key_bytes: [out_idx, ...]})."""
    groups = {}
    for out_idx, out in enumerate(outputs):
        if out.sp_data is None:
            continue
        sk_bytes = out.sp_data.scan_key.sec()
        if sk_bytes not in groups:
            groups[sk_bytes] = (out.sp_data.scan_key, [])
        groups[sk_bytes][1].append((out_idx, out.sp_data.spend_key))
    scan_spend_groups = {}
    output_indices = {}
    for sk_bytes, (scan_key, pairs) in groups.items():
        pairs.sort(key=lambda pair: (pair[1].sec(), pair[0]))
        scan_spend_groups[sk_bytes] = (scan_key, [spend for _, spend in pairs])
        output_indices[sk_bytes] = [out_idx for out_idx, _ in pairs]
    return scan_spend_groups, output_indices
