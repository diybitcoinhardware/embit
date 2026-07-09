"""
BIP-375 signing helpers: DLEQ proof wrappers and PSBT input private key
resolution.

These need HD key derivation / root / fingerprint, unlike the pure crypto
in sp.py.
"""

from ..base import EmbitError
from ..hashes import hash160, tagged_hash
from ..misc import urandom
from . import dleq
from .sp import SPFieldError, pubkey_hash_from_script


def _default_aux_rand(*secret_material):
    """Default aux_rand: fresh entropy hedged with the proof's private-key material."""
    return tagged_hash(
        "embit/DLEQDefaultAuxRand", urandom(32) + b"".join(secret_material)
    )


def compute_dleq_proof(a_sum_key, scan_key, aux_rand=None):
    """Generate a 64-byte DLEQ proof for an ECDH share (a_sum_key·B_scan).

    ``a_sum_key`` is a 32-byte scalar: the sum of the input keys for a global
    share, or a single input's key for a per-input share.
    """
    if aux_rand is None:
        aux_rand = _default_aux_rand(a_sum_key, scan_key.sec())
    try:
        return dleq.generate_dleq_proof(a_sum_key, scan_key.sec(), r=aux_rand)
    except dleq.DLEQError as e:
        raise SPFieldError("Failed to generate DLEQ proof: {}".format(e))


def match_sp_spend_base(inp, root, fingerprint, derive_hdkey):
    """Return the base PrivateKey for a BIP-376 SP-spend input, matched via
    sp_spend_bip32_derivations for fingerprint, or None.

    A raw key (no fingerprint) declares no derivation, so it matches only if
    its tweaked pubkey is the input's output key; inputs it does not control
    are skipped rather than failed."""
    if fingerprint:
        for pub_bytes, derivation in inp.sp_spend_bip32_derivations.items():
            if derivation.fingerprint != fingerprint:
                continue
            hdkey = derive_hdkey(root, derivation)
            if hdkey is not None and hdkey.sec() == pub_bytes:
                return hdkey.key
    if fingerprint is None and hasattr(root, "secret"):
        sp_tweak = inp.sp_tweak
        if sp_tweak is None or inp.script_pubkey is None:
            return None
        try:
            pk = root.sp_spend_tweak(sp_tweak)
        except (EmbitError, ValueError):
            return None
        if pk.xonly() == bytes(inp.script_pubkey.data[2:34]):
            return root
    return None


def _resolve_taproot_privkey(inp, root, fingerprint, derive_hdkey):
    """Resolve the private key for a taproot input."""
    output_xonly = bytes(inp.script_pubkey.data[2:34])

    sp_tweak = inp.sp_tweak
    if sp_tweak is not None:
        base = match_sp_spend_base(inp, root, fingerprint, derive_hdkey)
        if base is None:
            return None
        try:
            out_priv = base.sp_spend_tweak(sp_tweak).even_y()
        except (EmbitError, ValueError):
            return None
        return out_priv.secret if out_priv.xonly() == output_xonly else None

    merkle = inp.taproot_merkle_root or b""
    if fingerprint:
        for pub, (_leaves, derivation) in inp.taproot_bip32_derivations.items():
            if derivation.fingerprint != fingerprint:
                continue
            hdkey = derive_hdkey(root, derivation)
            if hdkey is None or hdkey.xonly() != pub.xonly():
                continue
            try:
                out_priv = hdkey.key.taproot_tweak(merkle)
            except (EmbitError, ValueError):
                continue
            if out_priv.xonly() == output_xonly:
                return out_priv.secret

    if fingerprint is None and hasattr(root, "secret"):
        try:
            out_priv = root.taproot_tweak(merkle)
        except (EmbitError, ValueError):
            return None
        if out_priv.xonly() == output_xonly:
            return out_priv.secret
    return None


def _resolve_bip32_privkey(inp, root, fingerprint, derive_hdkey):
    """Resolve the private key for non-taproot inputs via BIP32.

    The derivation and the pubkey it declares both come from the PSBT, so
    matching them only proves the PSBT is self-consistent. The scriptPubKey
    comes from the UTXO, so the hash it commits to is what actually binds a
    derived key to this input - without that check a PSBT could point us at a
    key we own for an input we do not, silently corrupting a_sum.
    """
    pkh = pubkey_hash_from_script(inp.script_pubkey, inp.redeem_script)
    if pkh is None:
        return None

    if fingerprint:
        for pub, derivation in inp.bip32_derivations.items():
            if derivation.fingerprint != fingerprint:
                continue
            hdkey = derive_hdkey(root, derivation)
            if hdkey is None or hdkey.sec() != pub.sec():
                continue
            if hash160(hdkey.sec()) != pkh:
                continue
            return hdkey.key.secret

    if fingerprint is None and hasattr(root, "secret"):
        if pkh == hash160(root.get_public_key().sec()):
            return root.secret
    return None


def resolve_input_privkey(inp, root, fingerprint, derive_hdkey):
    """Return the 32-byte private scalar for an eligible input's ECDH share,
    or None if root does not control the input."""
    if inp.script_pubkey is not None and inp.script_pubkey.script_type() == "p2tr":
        return _resolve_taproot_privkey(inp, root, fingerprint, derive_hdkey)
    return _resolve_bip32_privkey(inp, root, fingerprint, derive_hdkey)
