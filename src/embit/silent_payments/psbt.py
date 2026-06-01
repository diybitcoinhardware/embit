"""
SP-aware PSBT scopes and subclass.

Sections:
  1. SPInputScope / SPOutputScope — per-input/output BIP-375 field handlers
  2. SilentPaymentsPSBT — PSBT subclass with global SP fields and sign_with() SP hook
  3. finalize_sp_spends — BIP-376 finalizer for SP spend inputs
"""

import io
from collections import OrderedDict

from .. import ec, hashes
from ..base import EmbitError
from ..script import Witness
from ..psbt import (
    PSBT,
    DerivationPath,
    InputScope,
    OutputScope,
    PSBTError,
    SIGHASH,
    read_string,
    ser_string,
)
from . import dleq
from .ecdh import (
    compute_ecdh_share,
    compute_dleq_proof,
    get_eligible_inputs,
    pubkey_hash_from_script,
    input_public_key,
)
from .fields import SilentPaymentData, SPFieldError, SPValidationError

# ── scopes ────────────────────────────────────────────────────────────────────


class SPInputScope(InputScope):
    def __init__(self, *args, **kwargs):
        self.sp_ecdh_shares = OrderedDict()  # scan_key -> ecdh_share (33 bytes)
        self.sp_dleq_proofs = OrderedDict()  # scan_key -> dleq_proof (64 bytes)
        self.sp_spend_bip32_derivations = OrderedDict()  # pub_bytes -> DerivationPath
        self.sp_tweak = None  # 32 bytes or None
        super().__init__(*args, **kwargs)

    def clear_metadata(self, *args, **kwargs):
        super().clear_metadata(*args, **kwargs)
        self.sp_ecdh_shares = OrderedDict()
        self.sp_dleq_proofs = OrderedDict()
        self.sp_spend_bip32_derivations = OrderedDict()
        self.sp_tweak = None

    def update(self, other):
        super().update(other)
        if isinstance(other, SPInputScope):
            self.sp_ecdh_shares.update(other.sp_ecdh_shares)
            self.sp_dleq_proofs.update(other.sp_dleq_proofs)
            self.sp_spend_bip32_derivations.update(other.sp_spend_bip32_derivations)
            self.sp_tweak = other.sp_tweak or self.sp_tweak

    def read_value(self, stream, k, version=None):
        if k[0] == 0x1D:  # PSBT_IN_SP_ECDH_SHARE (BIP-375)
            v = read_string(stream)
            if version != 2:
                raise PSBTError("PSBT_IN_SP_ECDH_SHARE not allowed in PSBTv0")
            if len(k) != 34:
                raise PSBTError("Invalid PSBT_IN_SP_ECDH_SHARE key length")
            if len(v) != 33:
                raise PSBTError("PSBT_IN_SP_ECDH_SHARE value must be 33 bytes")
            scan_key = k[1:]
            if scan_key in self.sp_ecdh_shares:
                raise PSBTError("Duplicated PSBT_IN_SP_ECDH_SHARE for scan key")
            self.sp_ecdh_shares[scan_key] = v
        elif k[0] == 0x1E:  # PSBT_IN_SP_DLEQ (BIP-375)
            v = read_string(stream)
            if version != 2:
                raise PSBTError("PSBT_IN_SP_DLEQ not allowed in PSBTv0")
            if len(k) != 34:
                raise PSBTError("Invalid PSBT_IN_SP_DLEQ key length")
            if len(v) != 64:
                raise PSBTError("PSBT_IN_SP_DLEQ value must be 64 bytes")
            scan_key = k[1:]
            if scan_key in self.sp_dleq_proofs:
                raise PSBTError("Duplicated PSBT_IN_SP_DLEQ for scan key")
            self.sp_dleq_proofs[scan_key] = v
        elif k[0] == 0x1F:  # PSBT_IN_SP_SPEND_BIP32_DERIVATION (BIP-376)
            v = read_string(stream)
            if version != 2:
                raise PSBTError(
                    "PSBT_IN_SP_SPEND_BIP32_DERIVATION not allowed in PSBTv0"
                )
            if len(k) != 34:
                raise PSBTError("Invalid PSBT_IN_SP_SPEND_BIP32_DERIVATION key length")
            pub_bytes = k[1:]
            if pub_bytes in self.sp_spend_bip32_derivations:
                raise PSBTError(
                    "Duplicated PSBT_IN_SP_SPEND_BIP32_DERIVATION for pubkey"
                )
            self.sp_spend_bip32_derivations[pub_bytes] = DerivationPath.read_from(
                io.BytesIO(v)
            )
        elif k == b"\x20":  # PSBT_IN_SP_TWEAK (BIP-376)
            v = read_string(stream)
            if version != 2:
                raise PSBTError("PSBT_IN_SP_TWEAK not allowed in PSBTv0")
            if len(v) != 32:
                raise PSBTError("PSBT_IN_SP_TWEAK value must be 32 bytes")
            if self.sp_tweak is not None:
                raise PSBTError("Duplicated PSBT_IN_SP_TWEAK")
            self.sp_tweak = v
        else:
            super().read_value(stream, k, version=version)

    def write_to(self, stream, skip_separator=False, version=None, **kwargs) -> int:
        r = super().write_to(stream, skip_separator=True, version=version, **kwargs)
        if version == 2:
            for scan_key in self.sp_ecdh_shares:
                r += ser_string(stream, b"\x1d" + scan_key)
                r += ser_string(stream, self.sp_ecdh_shares[scan_key])
            for scan_key in self.sp_dleq_proofs:
                r += ser_string(stream, b"\x1e" + scan_key)
                r += ser_string(stream, self.sp_dleq_proofs[scan_key])
            for pub_bytes, derivation in self.sp_spend_bip32_derivations.items():
                r += ser_string(stream, b"\x1f" + pub_bytes)
                r += ser_string(stream, derivation.serialize())
            if self.sp_tweak is not None:
                r += ser_string(stream, b"\x20")
                r += ser_string(stream, self.sp_tweak)
        if not skip_separator:
            r += stream.write(b"\x00")
        return r


class SPOutputScope(OutputScope):
    def __init__(self, *args, **kwargs):
        self.sp_data = None  # SilentPaymentData (PSBT_OUT_SP_V0_INFO)
        self.sp_label = None  # uint32 label (PSBT_OUT_SP_V0_LABEL)
        super().__init__(*args, **kwargs)

    def clear_metadata(self, *args, **kwargs):
        super().clear_metadata(*args, **kwargs)
        self.sp_data = None
        self.sp_label = None

    def update(self, other):
        super().update(other)
        if isinstance(other, SPOutputScope):
            self.sp_data = other.sp_data or self.sp_data
            self.sp_label = (
                other.sp_label if other.sp_label is not None else self.sp_label
            )

    def read_value(self, stream, k, version=None):
        if k == b"\x09":  # PSBT_OUT_SP_V0_INFO (BIP-375)
            v = read_string(stream)
            if version != 2:
                raise PSBTError("PSBT_OUT_SP_V0_INFO not allowed in PSBTv0")
            if len(v) != 66:
                raise PSBTError("PSBT_OUT_SP_V0_INFO must be 66 bytes")
            if self.sp_data is not None:
                raise PSBTError("Duplicated PSBT_OUT_SP_V0_INFO")
            try:
                self.sp_data = SilentPaymentData.parse(v)
            except SPFieldError as e:
                raise PSBTError("Invalid PSBT_OUT_SP_V0_INFO: {}".format(e))
        elif k == b"\x0a":  # PSBT_OUT_SP_V0_LABEL (BIP-375)
            v = read_string(stream)
            if version != 2:
                raise PSBTError("PSBT_OUT_SP_V0_LABEL not allowed in PSBTv0")
            if len(v) != 4:
                raise PSBTError("PSBT_OUT_SP_V0_LABEL must be 4 bytes")
            if self.sp_label is not None:
                raise PSBTError("Duplicated PSBT_OUT_SP_V0_LABEL")
            self.sp_label = int.from_bytes(v, "little")
        else:
            super().read_value(stream, k, version=version)

    def write_to(self, stream, skip_separator=False, version=None, **kwargs) -> int:
        r = super().write_to(stream, skip_separator=True, version=version, **kwargs)
        if self.sp_data is not None:
            r += ser_string(stream, b"\x09")
            r += ser_string(stream, self.sp_data.serialize())
        if self.sp_label is not None:
            r += ser_string(stream, b"\x0a")
            r += ser_string(stream, self.sp_label.to_bytes(4, "little"))
        if not skip_separator:
            r += stream.write(b"\x00")
        return r


# ── PSBT subclass ─────────────────────────────────────────────────────────────


class SilentPaymentsPSBT(PSBT):
    PSBTIN_CLS = SPInputScope
    PSBTOUT_CLS = SPOutputScope

    def __init__(self, *args, **kwargs):
        self.sp_ecdh_shares = OrderedDict()  # scan_key -> ecdh_share (33 bytes)
        self.sp_dleq_proofs = OrderedDict()  # scan_key -> dleq_proof (64 bytes)
        super().__init__(*args, **kwargs)

    @classmethod
    def _validate_v2_output(cls, out, i):
        if out.value is None:
            raise PSBTError(
                "PSBTv2 output %d missing required PSBT_OUT_AMOUNT (0x03)" % i
            )
        if out.script_pubkey is None and getattr(out, "sp_data", None) is None:
            raise PSBTError(
                "PSBTv2 output %d missing required PSBT_OUT_SCRIPT (0x04)" % i
            )

    def add_output(self, output_scope):
        if not self.is_outputs_modifiable():
            raise PSBTError("Outputs are not modifiable")
        if self.version == 2:
            if output_scope.value is None:
                raise PSBTError("PSBTv2 output must have PSBT_OUT_AMOUNT")
            if (
                output_scope.script_pubkey is None
                and getattr(output_scope, "sp_data", None) is None
            ):
                raise PSBTError("PSBTv2 output must have PSBT_OUT_SCRIPT")
        self.outputs.append(output_scope)
        if self.version == 2:
            self._raw_output_count_from_global = len(self.outputs)

    def parse_unknowns(self):
        super().parse_unknowns()
        for k in list(self.unknown):
            if k[0] == 0x07 and len(k) == 34:  # PSBT_GLOBAL_SP_ECDH_SHARE
                if self.version != 2:
                    continue
                v = self.unknown.pop(k)
                if len(v) != 33:
                    raise PSBTError("PSBT_GLOBAL_SP_ECDH_SHARE value must be 33 bytes")
                scan_key = k[1:]
                if scan_key in self.sp_ecdh_shares:
                    raise PSBTError("Duplicated PSBT_GLOBAL_SP_ECDH_SHARE for scan key")
                self.sp_ecdh_shares[scan_key] = v
            elif k[0] == 0x08 and len(k) == 34:  # PSBT_GLOBAL_SP_DLEQ
                if self.version != 2:
                    continue
                v = self.unknown.pop(k)
                if len(v) != 64:
                    raise PSBTError("PSBT_GLOBAL_SP_DLEQ value must be 64 bytes")
                scan_key = k[1:]
                if scan_key in self.sp_dleq_proofs:
                    raise PSBTError("Duplicated PSBT_GLOBAL_SP_DLEQ for scan key")
                self.sp_dleq_proofs[scan_key] = v

    def _write_extra_globals(self, stream) -> int:
        r = 0
        if self.version == 2:
            for scan_key in self.sp_ecdh_shares:
                r += ser_string(stream, b"\x07" + scan_key)
                r += ser_string(stream, self.sp_ecdh_shares[scan_key])
            for scan_key in self.sp_dleq_proofs:
                r += ser_string(stream, b"\x08" + scan_key)
                r += ser_string(stream, self.sp_dleq_proofs[scan_key])
        return r

    def sign_with(self, root, sighash=None, **kwargs):
        has_sp = self.version == 2 and any(
            out.sp_data is not None for out in self.outputs
        )
        # BIP-375: only SIGHASH_ALL may be used when SP outputs are present.
        # SIGHASH.DEFAULT (taproot) is functionally SIGHASH_ALL.
        if (
            has_sp
            and sighash is not None
            and sighash not in (SIGHASH.ALL, SIGHASH.DEFAULT)
        ):
            raise SPValidationError(
                "Silent payment signing requires SIGHASH_ALL"
            )
        if sighash is not None:
            counter = super().sign_with(root, sighash=sighash, **kwargs)
        else:
            counter = super().sign_with(root, **kwargs)
        if has_sp:
            counter += self._sign_with_sp(root)
        if self.version == 2:
            counter += self._sign_sp_spends(root)
        return counter

    @staticmethod
    def _signing_fingerprint(root):
        """Resolve the signing fingerprint for ``root``.

        Returns ``(fingerprint, can_sign)``.  ``fingerprint`` is None for raw/WIF
        keys (which match by key material instead).  ``can_sign`` is False when
        ``root`` is a public-only descriptor key that cannot produce signatures.
        """
        fingerprint = None
        if hasattr(root, "origin"):
            if not getattr(root, "is_private", True):
                return None, False
            if getattr(root, "is_extended", False):
                fingerprint = root.fingerprint
        if not fingerprint and hasattr(root, "my_fingerprint"):
            fingerprint = root.my_fingerprint
        return fingerprint, True

    @staticmethod
    def _derive_hdkey(root, derivation):
        """Derive the HDKey for ``derivation``, honoring the root's origin prefix.

        Returns the derived HDKey, or None if the origin prefix doesn't match.
        """
        der = derivation.derivation
        if hasattr(root, "origin"):
            if root.origin:
                prefix = root.origin.derivation
                if der[: len(prefix)] != prefix:
                    return None
                der = der[len(prefix) :]
            return root.key.derive(der)
        return root.derive(der)

    def sign_input_with_sp_tweak(
        self,
        key: "ec.PrivateKey",
        input_index: int,
        inp=None,
        sighash=SIGHASH.DEFAULT,
    ) -> int:
        """BIP-376: sign a Silent Payment spend input using sp_tweak field."""
        inp = inp or self.inputs[input_index]
        sp_tweak = getattr(inp, "sp_tweak", None)
        if sp_tweak is None:
            return 0
        if not inp.is_taproot:
            return 0
        try:
            pk = key.sp_spend_tweak(sp_tweak)
        except (EmbitError, ValueError):
            return 0
        output_xonly = inp.utxo.script_pubkey.data[2:34]
        if pk.xonly() != output_xonly:
            return 0
        h = self.sighash(input_index, sighash=sighash)
        sig = pk.schnorr_sign(h)
        sigdata = sig.serialize()
        if sighash != SIGHASH.DEFAULT:
            sigdata += bytes([sighash])
        inp.taproot_key_sig = sigdata
        return 1

    def _sign_sp_spends(self, root) -> int:
        """BIP-376: sign inputs that carry sp_tweak using sp_spend_bip32_derivations."""
        fingerprint, can_sign = self._signing_fingerprint(root)
        if not can_sign:
            return 0

        counter = 0
        for i, inp in enumerate(self.inputs):
            if getattr(inp, "sp_tweak", None) is None:
                continue
            if inp.taproot_key_sig is not None:
                continue

            priv_key = None

            if fingerprint:
                for pub_bytes, derivation in inp.sp_spend_bip32_derivations.items():
                    if derivation.fingerprint != fingerprint:
                        continue
                    hdkey = self._derive_hdkey(root, derivation)
                    if hdkey is None or hdkey.xonly() != pub_bytes[1:]:
                        continue
                    priv_key = hdkey.key
                    break

            if priv_key is None and fingerprint is None and hasattr(root, "secret"):
                priv_key = root

            if priv_key is None:
                continue

            counter += self.sign_input_with_sp_tweak(priv_key, i, inp)

        return counter

    def _resolve_input_privkey(self, inp, root, fingerprint):
        """Return the 32-byte private scalar 'a' for an eligible input's ECDH
        share, or None if ``root`` does not control the input.

        For taproot inputs this is the (even-Y) output private key per the
        BIP-352 negation rule, obtained via taproot_tweak; for the other types
        it is the input key matched by derivation or by script hash.
        """
        is_taproot = (
            inp.script_pubkey is not None
            and inp.script_pubkey.script_type() == "p2tr"
        )

        if is_taproot:
            output_xonly = bytes(inp.script_pubkey.data[2:34])
            merkle = inp.taproot_merkle_root or b""
            if fingerprint:
                for pub, (_leaves, derivation) in (
                    inp.taproot_bip32_derivations.items()
                ):
                    if derivation.fingerprint != fingerprint:
                        continue
                    hdkey = self._derive_hdkey(root, derivation)
                    if hdkey is None or hdkey.xonly() != pub.xonly():
                        continue
                    out_priv = hdkey.key.taproot_tweak(merkle)
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

        if fingerprint:
            for pub, derivation in inp.bip32_derivations.items():
                if derivation.fingerprint != fingerprint:
                    continue
                hdkey = self._derive_hdkey(root, derivation)
                if hdkey is None or hdkey.xonly() != pub.xonly():
                    continue
                return hdkey.key.secret

        if fingerprint is None and hasattr(root, "secret"):
            pkh = pubkey_hash_from_script(inp.script_pubkey, inp.redeem_script)
            if pkh is not None and pkh == hashes.hash160(root.get_public_key().sec()):
                return root.secret

        return None

    def _verify_existing_sp_shares(self, eligible, scan_keys) -> None:
        """Verify DLEQ proofs of ECDH shares already present on eligible inputs.

        Raises SPValidationError if a present share lacks a proof or its proof
        fails to verify against the input's public key.
        """
        for i in eligible:
            inp = self.inputs[i]
            pubkey = input_public_key(inp)
            for sk_bytes in scan_keys:
                if sk_bytes not in inp.sp_ecdh_shares:
                    continue
                proof = inp.sp_dleq_proofs.get(sk_bytes)
                if proof is None:
                    raise SPValidationError(
                        "Input %d has an SP ECDH share without a DLEQ proof" % i
                    )
                if pubkey is None:
                    # Cannot resolve the input key to verify; leave the share as
                    # provided (a malformed share is caught later by validation).
                    continue
                if not dleq.verify_dleq_proof(
                    pubkey.sec(), sk_bytes, inp.sp_ecdh_shares[sk_bytes], proof
                ):
                    raise SPValidationError(
                        "Input %d has an invalid SP ECDH share DLEQ proof" % i
                    )

    def _sign_with_sp(self, root, aux_rand=None) -> int:
        """Compute per-input ECDH shares and DLEQ proofs for SP outputs."""
        scan_keys = {}
        for out in self.outputs:
            if out.sp_data is not None:
                sk_bytes = out.sp_data.scan_key.sec()
                if sk_bytes not in scan_keys:
                    scan_keys[sk_bytes] = out.sp_data.scan_key

        if not scan_keys:
            return 0

        try:
            eligible = get_eligible_inputs(self.inputs, has_sp_outputs=True)
        except SPValidationError:
            return 0

        if not eligible:
            return 0

        # BIP-375: verify ECDH shares already present (added by other signers)
        # using their DLEQ proofs before contributing our own, so we never
        # endorse an invalid share by adding to the same PSBT.
        self._verify_existing_sp_shares(eligible, scan_keys)

        fingerprint, can_sign = self._signing_fingerprint(root)
        if not can_sign:
            return 0

        counter = 0

        for i in eligible:
            inp = self.inputs[i]

            priv_bytes = self._resolve_input_privkey(inp, root, fingerprint)
            if priv_bytes is None:
                continue

            for sk_bytes, scan_key in scan_keys.items():
                if sk_bytes in inp.sp_ecdh_shares:
                    continue
                try:
                    share = compute_ecdh_share(priv_bytes, scan_key)
                    proof = compute_dleq_proof(
                        priv_bytes, scan_key, share, aux_rand=aux_rand
                    )
                    inp.sp_ecdh_shares[sk_bytes] = share
                    inp.sp_dleq_proofs[sk_bytes] = proof
                    counter += 1
                except SPFieldError:
                    continue

        return counter


# ── BIP-376 finalizer ───────────────────────────────────────────────────────────


def finalize_sp_spends(psbt) -> int:
    """
    BIP-376 Finalizer: for each signed SP spend input, construct the final
    scriptwitness from taproot_key_sig and clear SP-specific fields.

    Returns number of inputs finalized.
    """
    count = 0
    for inp in psbt.inputs:
        if getattr(inp, "sp_tweak", None) is None:
            continue
        if inp.taproot_key_sig is None:
            continue
        inp.final_scriptwitness = Witness([inp.taproot_key_sig])
        inp.taproot_key_sig = None
        inp.sp_tweak = None
        inp.sp_spend_bip32_derivations = OrderedDict()
        count += 1
    return count
