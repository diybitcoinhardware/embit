"""
SP-aware PSBT scopes, subclass, and signing orchestrator.

Sections:
  1. SPInputScope / SPOutputScope — per-input/output BIP-375 field handlers
  2. SilentPaymentsPSBT — PSBT subclass with global SP fields and sign_with() SP hook
  3. SPSigner — high-level signing wrapper (clear → populate → validate → sign)
"""

from collections import OrderedDict

from .. import hashes
from ..psbt import (
    PSBT,
    InputScope,
    OutputScope,
    PSBTError,
    SIGHASH,
    read_string,
    ser_string,
)

# this needs bip352, psbtv2 and dleq PRs to be merged first.
from .ecdh import compute_ecdh_share, compute_dleq_proof, get_eligible_inputs
from .fields import SilentPaymentData, SPFieldError, SPValidationError

# ── scopes ────────────────────────────────────────────────────────────────────


class SPInputScope(InputScope):
    def __init__(self, *args, **kwargs):
        self.sp_ecdh_shares = OrderedDict()  # scan_key -> ecdh_share (33 bytes)
        self.sp_dleq_proofs = OrderedDict()  # scan_key -> dleq_proof (64 bytes)
        super().__init__(*args, **kwargs)

    def clear_metadata(self, *args, **kwargs):
        super().clear_metadata(*args, **kwargs)
        self.sp_ecdh_shares = OrderedDict()
        self.sp_dleq_proofs = OrderedDict()

    def update(self, other):
        super().update(other)
        if isinstance(other, SPInputScope):
            self.sp_ecdh_shares.update(other.sp_ecdh_shares)
            self.sp_dleq_proofs.update(other.sp_dleq_proofs)

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
                raise PSBTError(f"Invalid PSBT_OUT_SP_V0_INFO: {e}")
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
            if output_scope.script_pubkey is None and getattr(output_scope, "sp_data", None) is None:
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
        if sighash is not None:
            counter = super().sign_with(root, sighash=sighash, **kwargs)
        else:
            counter = super().sign_with(root, **kwargs)
        if self.version == 2 and any(out.sp_data is not None for out in self.outputs):
            counter += self._sign_with_sp(root)
        return counter

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

        fingerprint = None
        if hasattr(root, "origin"):
            if not getattr(root, "is_private", True):
                return 0
            if getattr(root, "is_extended", False):
                fingerprint = root.fingerprint
        if not fingerprint and hasattr(root, "my_fingerprint"):
            fingerprint = root.my_fingerprint

        counter = 0

        for i in eligible:
            inp = self.inputs[i]

            priv_bytes = None
            if fingerprint:
                for pub, derivation in inp.bip32_derivations.items():
                    if derivation.fingerprint != fingerprint:
                        continue
                    der = derivation.derivation
                    if hasattr(root, "origin"):
                        if root.origin:
                            prefix = root.origin.derivation
                            if der[: len(prefix)] != prefix:
                                continue
                            der = der[len(prefix) :]
                        hdkey = root.key.derive(der)
                    else:
                        hdkey = root.derive(der)
                    if hdkey.xonly() != pub.xonly():
                        continue
                    priv_bytes = hdkey.key.secret
                    break

            if priv_bytes is None and fingerprint is None and hasattr(root, "secret"):
                sp = inp.script_pubkey
                if sp is not None:
                    root_pub = root.get_public_key()
                    pkh = hashes.hash160(root_pub.sec())
                    if root_pub.sec() in sp.data or pkh in sp.data:
                        priv_bytes = root.secret

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


# ── signing orchestrator ──────────────────────────────────────────────────────


class SPSigner:
    """
    Orchestrates the BIP-375 signing sequence:
      1. Discard any incoming SP fields (untrusted).
      2. Populate fresh ECDH shares + DLEQ proofs with caller-supplied entropy.
      3. Run full BIP-375 structural validation.
      4. Sign all inputs.
    """

    def __init__(self, psbt):
        self.psbt = psbt

    def _sp_aux_rand(self):
        """Return 32 bytes of fresh auxiliary randomness for DLEQ proof generation."""
        import os as _os

        return _os.urandom(32)

    def _populate_silent_payment_outputs(self, root, aux_rand=None):
        """
        Discard incoming SP fields then compute fresh ECDH shares + DLEQ proofs.

        Returns number of (ECDH-share, DLEQ-proof) pairs added.
        """
        for inp in self.psbt.inputs:
            inp.sp_ecdh_shares = OrderedDict()
            inp.sp_dleq_proofs = OrderedDict()
        self.psbt.sp_ecdh_shares = OrderedDict()
        self.psbt.sp_dleq_proofs = OrderedDict()

        if aux_rand is None:
            aux_rand = self._sp_aux_rand()
        return self.psbt._sign_with_sp(root, aux_rand=aux_rand)

    def sign(self, root, sighash=SIGHASH.DEFAULT):
        """
        Sign the PSBT, handling SP outputs correctly.

        For PSBTs with SP outputs:
          - Discards untrusted SP fields from the incoming PSBT.
          - Populates fresh ECDH shares + DLEQ proofs.
          - Validates BIP-375 structure (raises SPValidationError on failure).
          - Signs all inputs.

        Returns number of signatures (+ SP field pairs) added.
        Raises SPValidationError if the PSBT is not valid for SP signing.
        """
        has_sp = any(out.sp_data is not None for out in self.psbt.outputs)

        if has_sp and self.psbt.version != 2:
            raise SPValidationError("SP signing requires PSBTv2")

            get_eligible_inputs(self.psbt.inputs, has_sp_outputs=True)
            self._populate_silent_payment_outputs(root)


        return self.psbt.sign_with(root, sighash=sighash)
