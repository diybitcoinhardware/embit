"""
SP-aware PSBT scopes and subclass.

Sections:
  1. SPInputScope / SPOutputScope — per-input/output BIP-375 field handlers
  2. SilentPaymentsPSBT — PSBT subclass with global SP fields and sign_with() SP hook
"""

from collections import OrderedDict

from .. import ec
from ..base import EmbitError
from ..script import Script
from ..psbt import (
    PSBT,
    CompressMode,
    DerivationPath,
    InputScope,
    OutputScope,
    PSBTError,
    SIGHASH,
    TxModifiable,
    derive_hdkey,
    read_string,
    resolve_signing_root,
    ser_string,
)
from . import dleq
from .sp import (
    SPFieldError,
    SPValidationError,
    derive_sp_outputs,
    get_eligible_inputs,
    group_sp_outputs_by_scan_key,
    witness_version,
)
from .signing import (
    compute_dleq_proof,
    match_sp_spend_base,
    resolve_input_privkey,
)


class SilentPaymentData:
    """Represents PSBT_OUT_SP_V0_INFO field (scan key + spend key)."""

    def __init__(self, scan_key: ec.PublicKey, spend_key: ec.PublicKey):
        self.scan_key = scan_key
        self.spend_key = spend_key

    def serialize(self) -> bytes:
        """Serialize as 33-byte scan key + 33-byte spend key."""
        return self.scan_key.sec() + self.spend_key.sec()

    @classmethod
    def parse(cls, data: bytes) -> "SilentPaymentData":
        """Parse from 66 bytes (33-byte scan key + 33-byte spend key)."""
        if len(data) != 66:
            raise SPFieldError(
                "PSBT_OUT_SP_V0_INFO must be 66 bytes, got {}".format(len(data))
            )
        try:
            scan_key = ec.PublicKey.parse(data[:33])
            spend_key = ec.PublicKey.parse(data[33:66])
            return cls(scan_key, spend_key)
        except EmbitError as e:
            raise SPFieldError("Invalid SP data: {}".format(e))


class SPInputScope(InputScope):
    # PSBT_IN_SP_TWEAK carries no keydata. Listing it here is what makes the
    # base _validate_key() reject a key with trailing bytes, instead of
    # letting it fall through to `unknown` and be re-serialized verbatim.
    V2_FIELDS = InputScope.V2_FIELDS + (b"\x20",)

    # BIP-375 per-input fields this class does not model yet (multi-party SP
    # sends). They still have to be validated on the way in - the BIP-375
    # vectors declare a malformed one invalid, and surviving as an unknown
    # field would re-serialize it verbatim.
    # {key type: (name, value length)}
    _SP_PER_INPUT_SHARE_FIELDS = {
        0x1D: ("PSBT_IN_SP_ECDH_SHARE", 33),
        0x1E: ("PSBT_IN_SP_DLEQ", 64),
    }

    def __init__(self, *args, **kwargs):
        self.sp_spend_bip32_derivations = OrderedDict()  # pub_bytes -> DerivationPath
        self.sp_tweak = None  # 32 bytes or None
        super().__init__(*args, **kwargs)

    def clear_metadata(self, compress=CompressMode.CLEAR_ALL):
        super().clear_metadata(compress)
        # The base contract makes KEEP_ALL a no-op; wiping the BIP-376 fields
        # anyway leaves an SP-spend input that can no longer be signed.
        if compress == CompressMode.KEEP_ALL:
            return
        self.sp_spend_bip32_derivations = OrderedDict()
        self.sp_tweak = None

    def update(self, other):
        super().update(other)
        if isinstance(other, SPInputScope):
            self.sp_spend_bip32_derivations.update(other.sp_spend_bip32_derivations)
            self.sp_tweak = other.sp_tweak or self.sp_tweak

    def __eq__(self, other):
        # EmbitBase.__eq__ serializes with the default version=None, which writes
        # none of the v2-only fields - two scopes differing only in SP data would
        # compare equal. Pin the version so the comparison sees them.
        return type(self) is type(other) and (
            self.serialize(version=2) == other.serialize(version=2)
        )

    __hash__ = InputScope.__hash__

    def read_value(self, stream, k, version=None):
        # PSBT_IN_SP_ECDH_SHARE / PSBT_IN_SP_DLEQ are validated on the way in
        # (see _SP_PER_INPUT_SHARE_FIELDS) and kept as unknowns, never modelled:
        # BIP-375 lets a Signer holding every eligible input's key set one
        # global share instead, which is all this class ever does - and it is
        # the smaller encoding. Modelling them is only needed for multi-party
        # sends, where a signer contributes a share for some inputs only.
        if len(k) == 0:  # separator - the base swallows it, so k[0] is unsafe
            return
        if k[0] == 0x1F:  # PSBT_IN_SP_SPEND_BIP32_DERIVATION (BIP-376)
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
            self.sp_spend_bip32_derivations[pub_bytes] = DerivationPath.parse(v)
        elif k == b"\x20":  # PSBT_IN_SP_TWEAK (BIP-376)
            v = read_string(stream)
            if version != 2:
                raise PSBTError("PSBT_IN_SP_TWEAK not allowed in PSBTv0")
            if len(v) != 32:
                raise PSBTError("PSBT_IN_SP_TWEAK value must be 32 bytes")
            if self.sp_tweak is not None:
                raise PSBTError("Duplicated PSBT_IN_SP_TWEAK")
            self.sp_tweak = v
        elif k[0] in self._SP_PER_INPUT_SHARE_FIELDS:
            name, size = self._SP_PER_INPUT_SHARE_FIELDS[k[0]]
            v = read_string(stream)
            if version != 2:
                raise PSBTError("%s not allowed in PSBTv0" % name)
            if len(k) != 34:
                raise PSBTError("Invalid %s key length" % name)
            if len(v) != size:
                raise PSBTError("%s value must be %d bytes" % (name, size))
            if k in self.unknown:
                raise PSBTError("Duplicated %s" % name)
            self.unknown[k] = v
        else:
            super().read_value(stream, k, version=version)

    def write_to(self, stream, skip_separator=False, version=None, **kwargs) -> int:
        r = super().write_to(stream, skip_separator=True, version=version, **kwargs)
        if version == 2:
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
    # Neither field carries keydata; see SPInputScope.V2_FIELDS.
    V2_FIELDS = OutputScope.V2_FIELDS + (b"\x09", b"\x0a")

    def __init__(self, *args, **kwargs):
        self.sp_data = None  # SilentPaymentData (PSBT_OUT_SP_V0_INFO)
        self.sp_label = None  # uint32 label (PSBT_OUT_SP_V0_LABEL)
        super().__init__(*args, **kwargs)

    def clear_metadata(self, compress=CompressMode.CLEAR_ALL):
        super().clear_metadata(compress)
        # The base contract makes KEEP_ALL a no-op.
        if compress == CompressMode.KEEP_ALL:
            return
        self.sp_label = None
        # sp_data is only metadata once the script it stands in for exists.
        # Before that it is the output's whole definition, and dropping it
        # leaves an output that fails _validate_v2_output - a PSBT that can no
        # longer be parsed. The base keeps script_pubkey/value for that reason.
        if self.script_pubkey is not None:
            self.sp_data = None

    def update(self, other):
        super().update(other)
        if isinstance(other, SPOutputScope):
            self.sp_data = other.sp_data or self.sp_data
            self.sp_label = (
                other.sp_label if other.sp_label is not None else self.sp_label
            )

    def __eq__(self, other):
        # See SPInputScope.__eq__.
        return type(self) is type(other) and (
            self.serialize(version=2) == other.serialize(version=2)
        )

    __hash__ = OutputScope.__hash__

    def read_value(self, stream, k, version=None):
        if k == b"\x09":  # PSBT_OUT_SP_V0_INFO (BIP-375)
            v = read_string(stream)
            if version != 2:
                raise PSBTError("PSBT_OUT_SP_V0_INFO not allowed in PSBTv0")
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
        if version == 2:
            if self.sp_data is not None:
                r += ser_string(stream, b"\x09")
                r += ser_string(stream, self.sp_data.serialize())
            if self.sp_label is not None:
                r += ser_string(stream, b"\x0a")
                r += ser_string(stream, self.sp_label.to_bytes(4, "little"))
        if not skip_separator:
            r += stream.write(b"\x00")
        return r


class SilentPaymentsPSBT(PSBT):
    PSBTIN_CLS = SPInputScope
    PSBTOUT_CLS = SPOutputScope

    def __init__(self, *args, **kwargs):
        self.sp_ecdh_shares = OrderedDict()  # scan_key -> ecdh_share (33 bytes)
        self.sp_dleq_proofs = OrderedDict()  # scan_key -> dleq_proof (64 bytes)
        super().__init__(*args, **kwargs)

    def __eq__(self, other):
        # Same reason SPInputScope.__eq__ pins the type: the base compares
        # serializations only, so a plain PSBT can compare equal and then blow
        # up on the SP attributes it does not have.
        if type(self) is not type(other) or not super().__eq__(other):
            return False
        return (
            self.sp_ecdh_shares == other.sp_ecdh_shares
            and self.sp_dleq_proofs == other.sp_dleq_proofs
        )

    __hash__ = PSBT.__hash__

    @property
    def has_sp_outputs(self) -> bool:
        """Whether this PSBT has any Silent Payment output (BIP-375)."""
        # add_output()/PSBTOUT_CLS guarantee every output is an SPOutputScope.
        return any(out.sp_data is not None for out in self.outputs)

    @classmethod
    def _validate_v2_output(cls, out, i):
        """Same as PSBT._validate_v2_output, but SP outputs may omit
        PSBT_OUT_SCRIPT (the taproot script is derived from ECDH shares, not
        known up front). Used by both the parser and add_output() (see
        base PSBT.add_output)."""
        if not cls._v2_output_has_amount(out):
            raise PSBTError(
                "PSBTv2 output %d missing required PSBT_OUT_AMOUNT (0x03)" % i
            )
        if out.script_pubkey is None and out.sp_data is None:
            raise PSBTError(
                "PSBTv2 output %d missing required PSBT_OUT_SCRIPT (0x04)" % i
            )
        if out.sp_label is not None and out.sp_data is None:
            raise PSBTError(
                "PSBTv2 output %d has PSBT_OUT_SP_V0_LABEL without "
                "PSBT_OUT_SP_V0_INFO" % i
            )

    def add_input(self, input_scope):
        # SPInputScope is a strict superset of InputScope, so a plain scope is
        # always a caller mistake: it can never carry the BIP-376 fields and
        # would silently drop them on serialization.
        if not isinstance(input_scope, self.PSBTIN_CLS):
            raise PSBTError("SilentPaymentsPSBT requires SPInputScope inputs")
        super().add_input(input_scope)

    def add_output(self, output_scope):
        if not isinstance(output_scope, self.PSBTOUT_CLS):
            raise PSBTError("SilentPaymentsPSBT requires SPOutputScope outputs")
        super().add_output(output_scope)

    # BIP-375 global fields: {key type: (name, target attribute, value length)}
    _SP_GLOBAL_FIELDS = {
        0x07: ("PSBT_GLOBAL_SP_ECDH_SHARE", "sp_ecdh_shares", 33),
        0x08: ("PSBT_GLOBAL_SP_DLEQ", "sp_dleq_proofs", 64),
    }

    def parse_unknowns(self):
        super().parse_unknowns()
        for k in list(self.unknown):
            field = self._SP_GLOBAL_FIELDS.get(k[0])
            if field is None:
                continue
            name, attr, size = field
            # Malformed keydata used to survive as an unknown field and get
            # re-serialized verbatim; the per-input/output SP fields reject
            # both cases, so these do too.
            if self.version != 2:
                raise PSBTError("%s not allowed in PSBTv0" % name)
            if len(k) != 34:
                raise PSBTError("Invalid %s key length" % name)
            v = self.unknown.pop(k)
            if len(v) != size:
                raise PSBTError("%s value must be %d bytes" % (name, size))
            getattr(self, attr)[k[1:]] = v

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

    # BIP-375: only SIGHASH_ALL may be used when SP outputs are present.
    # SIGHASH.DEFAULT (taproot) is functionally SIGHASH_ALL.
    _SP_ALLOWED_SIGHASHES = (SIGHASH.ALL, SIGHASH.DEFAULT)

    def _assert_sp_sighash_all(self, sighash):
        """Raise unless every signature this pass could produce is SIGHASH_ALL."""
        if sighash is not None:
            if sighash not in self._SP_ALLOWED_SIGHASHES:
                raise SPValidationError("Silent payment signing requires SIGHASH_ALL")
            return
        # sighash=None means "use the sighash each input asks for", so the
        # per-input requests are what has to be checked.
        for i, inp in enumerate(self.inputs):
            if (
                inp.sighash_type is not None
                and inp.sighash_type not in self._SP_ALLOWED_SIGHASHES
            ):
                raise SPValidationError(
                    "Silent payment signing requires SIGHASH_ALL, but input "
                    "%d requests sighash 0x%02x" % (i, inp.sighash_type)
                )

    def validate_sp(self) -> None:
        """BIP-375 checks a signer makes on a PSBT it did not build itself."""
        if self.version != 2 or not self.has_sp_outputs:
            return

        # BIP-375: "If any input is spending an output with script using
        # Segwit version > 1, the Signer must fail."
        for i, inp in enumerate(self.inputs):
            script = inp.script_pubkey
            if script is None:
                raise SPValidationError(
                    "Input %d has no UTXO; cannot determine SP eligibility" % i
                )
            wv = witness_version(script)
            if wv is not None and wv > 1:
                raise SPValidationError(
                    "Input %d spends a Segwit version > 1 output with SP " "outputs" % i
                )

        if (self.is_inputs_modifiable() or self.is_outputs_modifiable()) and any(
            out.sp_data is not None and out.script_pubkey is not None
            for out in self.outputs
        ):
            raise SPValidationError(
                "PSBT_GLOBAL_TX_MODIFIABLE Inputs/Outputs Modifiable flags not "
                "cleared for PSBT with computed scripts for SP outputs"
            )

        # None: check what each input asks for, not one sighash for the pass.
        self._assert_sp_sighash_all(None)

        scan_keys = {out.sp_data.scan_key.sec() for out in self.outputs if out.sp_data}
        for scan_key in scan_keys:
            if (scan_key in self.sp_ecdh_shares) != (scan_key in self.sp_dleq_proofs):
                raise SPValidationError(
                    "PSBT_GLOBAL_SP_ECDH_SHARE and PSBT_GLOBAL_SP_DLEQ must both be "
                    "present for scan key %s" % scan_key.hex()
                )

    def sign_with(self, root, sighash=SIGHASH.DEFAULT, aux_rand=None):
        if self.version != 2 and self.has_sp_outputs:
            raise SPValidationError("Silent Payment signing requires PSBTv2")

        # A Descriptor has to be split into its keys to sign: the SP spend path
        # resolves a fingerprint from the root, and a Descriptor has no key
        # material of its own to resolve. A public-only key signs nothing, and
        # the SP send probes `root` for key material in a way that raises on
        # one, so drop it here - the contract PSBT.sign_with() honours.
        keys = [
            k
            for k in (root.keys if hasattr(root, "keys") else [root])
            if resolve_signing_root(k)[1]
        ]
        if not keys:
            return 0

        # The send is derived once for the whole root, not once per key: every
        # eligible input feeds a single a_sum, so re-deriving per key aborts on
        # the second key, which controls none of the inputs the first consumed.
        if self.has_sp_outputs:
            self._assert_sp_sighash_all(sighash)
            self.derive_sp_outputs(root, aux_rand=aux_rand)

        counter = 0
        for k in keys:
            counter += super().sign_with(k, sighash=sighash)
            counter += self._sign_sp_spends(k, sighash=sighash)
        return counter

    def sign_input_with_sp_tweak(
        self,
        key: "ec.PrivateKey",
        input_index: int,
        inp=None,
        sighash=SIGHASH.DEFAULT,
    ) -> int:
        """BIP-376: sign a Silent Payment spend input using sp_tweak field.

        Raises SPValidationError for anything that is not a signable SP-spend
        input.
        """
        inp = inp or self.inputs[input_index]
        sp_tweak = inp.sp_tweak
        if sp_tweak is None:
            raise SPValidationError(
                "Input %d is not a Silent Payment spend input (missing sp_tweak)"
                % input_index
            )
        if inp.utxo is None:
            raise SPValidationError(
                "Input %d has no UTXO; cannot verify the sp_tweak against the "
                "output key" % input_index
            )
        if not inp.is_taproot:
            raise SPValidationError(
                "Input %d is not a Silent Payment spend input (not a Taproot input)"
                % input_index
            )
        try:
            pk = key.sp_spend_tweak(sp_tweak)
        except (EmbitError, ValueError):
            raise SPValidationError("Input %d has invalid sp_tweak" % input_index)
        output_xonly = inp.utxo.script_pubkey.data[2:34]
        if pk.xonly() != output_xonly:
            raise SPValidationError(
                "Input %d has mismatched sp_tweak and output key" % input_index
            )
        counter = self._sign_taproot_keypath(pk, input_index, inp, sighash)
        # BIP-370 Signer role: the signature commits to the inputs/outputs this
        # sighash covers, so they are no longer modifiable. PSBT.sign_with()
        # does this for every signature it adds; this path has to do it too.
        self._update_tx_modifiable(sighash)
        return counter

    def _sign_sp_spends(self, root, sighash=SIGHASH.DEFAULT) -> int:
        """BIP-376: sign inputs that carry sp_tweak using sp_spend_bip32_derivations."""
        fingerprint, can_sign, root = resolve_signing_root(root)
        if not can_sign:
            return 0

        counter = 0
        for i, inp in enumerate(self.inputs):
            if inp.sp_tweak is None:
                continue
            if inp.taproot_key_sig is not None:
                continue

            inp_sighash = inp.sighash_type
            if inp_sighash is None:
                inp_sighash = SIGHASH.DEFAULT if sighash is None else sighash
            if sighash is not None and inp_sighash != sighash:
                if (
                    inp_sighash not in self._SP_ALLOWED_SIGHASHES
                    or sighash not in self._SP_ALLOWED_SIGHASHES
                ):
                    continue

            priv_key = match_sp_spend_base(inp, root, fingerprint, derive_hdkey)
            if priv_key is None:
                continue

            counter += self.sign_input_with_sp_tweak(
                priv_key, i, inp, sighash=inp_sighash
            )

        return counter

    def derive_sp_outputs(self, root, aux_rand=None) -> None:
        """BIP-375 single-signer Silent Payment send: this signer controls
        every eligible input and acts as its own output generator.

        Resolves the input private keys from ``root``, then hands off to
        derive_sp_outputs_from_keys() for the derivation itself.

        Raises SPValidationError if an eligible input is not controlled by
        ``root`` (multi-party Silent Payment sends are out of scope for a
        stateless single-party signer), or if no eligible input matches
        ``root`` at all.
        """
        self.derive_sp_outputs_from_keys(
            self._resolve_sp_privkeys(root), aux_rand=aux_rand
        )

    def _resolve_sp_privkeys(self, root) -> list:
        """Private scalars of every eligible input, resolved from ``root``.

        A Descriptor is tried key by key per input: its keys belong to one
        signer, so a send whose eligible inputs are spread across them is
        still single-party.
        """
        eligible = get_eligible_inputs(self.inputs)

        signers = [
            (fingerprint, r)
            for fingerprint, can_sign, r in (
                resolve_signing_root(k)
                for k in (root.keys if hasattr(root, "keys") else [root])
            )
            if can_sign
        ]
        priv_keys = []
        foreign_inputs = []
        for i in eligible:
            priv = None
            for fingerprint, r in signers:
                priv = resolve_input_privkey(
                    self.inputs[i], r, fingerprint, derive_hdkey
                )
                if priv is not None:
                    break
            if priv is None:
                foreign_inputs.append(i)
            else:
                priv_keys.append(priv)

        if foreign_inputs:
            if priv_keys:
                raise SPValidationError(
                    "Silent Payment signing failed: input(s) {} belong to another "
                    "signer; multi-party Silent Payment sends are not "
                    "supported.".format(", ".join(str(i) for i in foreign_inputs))
                )
            raise SPValidationError(
                "Silent Payment signing failed: no eligible input is controlled "
                "by this seed (check derivation / fingerprint)."
            )

        return priv_keys

    def derive_sp_outputs_from_keys(self, priv_keys, aux_rand=None) -> None:
        """Derive the Silent Payment outputs from explicit private scalars.

        Anything this PSBT already declares - PSBT_OUT_SCRIPT, global ECDH
        shares, global DLEQ proofs - must agree with the derivation, otherwise
        SPValidationError is raised and the PSBT is left untouched.
        """
        # validate_sp() is a no-op outside v2, and _write_extra_globals() drops
        # the shares it would produce, so a v0 PSBT has to fail here rather
        # than derive into fields that are silently thrown away on serialize.
        if self.version != 2:
            raise SPValidationError("Silent Payment signing requires PSBTv2")
        self.validate_sp()

        if not self.has_sp_outputs:
            raise SPValidationError(
                "Silent Payment send requires at least one output with "
                "PSBT_OUT_SP_V0_INFO."
            )
        if not priv_keys:
            raise SPValidationError(
                "Silent Payment send requires at least one eligible input "
                "(P2PKH, P2SH-P2WPKH, P2WPKH, or P2TR)."
            )

        scan_spend_groups, output_indices = group_sp_outputs_by_scan_key(self.outputs)

        derivation = derive_sp_outputs(
            priv_keys, [inp.vin for inp in self.inputs], scan_spend_groups
        )
        if derivation is None:
            raise SPValidationError(
                "Silent Payment signing failed: private key sum is zero."
            )

        a_sum_bytes, A_sum_sec, results = derivation
        scripts = self._verify_declared_sp(A_sum_sec, results, output_indices)
        # Every proof is generated before anything is written: compute_dleq_proof
        # raises on bad aux_rand, and a half-applied derivation leaves shares
        # without their proofs - a state validate_sp() rejects forever, so the
        # PSBT could never be signed again.
        proofs = {
            sk_bytes: compute_dleq_proof(
                a_sum_bytes, scan_spend_groups[sk_bytes][0], aux_rand=aux_rand
            )
            for sk_bytes in results
        }

        self.sp_ecdh_shares.clear()
        self.sp_dleq_proofs.clear()
        for inp in self.inputs:
            keys_to_delete = [
                k
                for k in inp.unknown
                if len(k) > 0 and k[0] in SPInputScope._SP_PER_INPUT_SHARE_FIELDS
            ]
            for k in keys_to_delete:
                del inp.unknown[k]

        for sk_bytes, (ecdh_share, _outputs) in results.items():
            self.sp_ecdh_shares[sk_bytes] = ecdh_share
            self.sp_dleq_proofs[sk_bytes] = proofs[sk_bytes]
        for out_idx, script in scripts.items():
            self.outputs[out_idx].script_pubkey = script

        # BIP-375: a Signer that sets any missing PSBT_OUT_SCRIPT must clear
        # Inputs Modifiable and Outputs Modifiable.
        if self.tx_modifiable_flags is not None:
            self.tx_modifiable_flags &= ~(TxModifiable.INPUTS | TxModifiable.OUTPUTS)

    def _verify_declared_sp(self, A_sum_sec, results, output_indices):
        """Check the derivation against whatever this PSBT already declares.

        Returns {output_index: derived Script} so the caller can apply the
        derivation only once every declared value has been accepted.
        """
        scripts = {}
        for sk_bytes, (ecdh_share, outputs) in results.items():
            declared_share = self.sp_ecdh_shares.get(sk_bytes)
            if declared_share is not None and declared_share != ecdh_share:
                raise SPValidationError(
                    "PSBT_GLOBAL_SP_ECDH_SHARE for scan key %s does not match the "
                    "derived share" % sk_bytes.hex()
                )
            declared_proof = self.sp_dleq_proofs.get(sk_bytes)
            if declared_proof is not None and not dleq.verify_dleq_proof(
                A_sum_sec, sk_bytes, ecdh_share, declared_proof
            ):
                raise SPValidationError(
                    "PSBT_GLOBAL_SP_DLEQ for scan key %s does not verify"
                    % sk_bytes.hex()
                )
            for pos, out_idx in enumerate(output_indices[sk_bytes]):
                script = Script(b"\x51\x20" + outputs[pos])
                declared_script = self.outputs[out_idx].script_pubkey
                if declared_script is not None and declared_script != script:
                    raise SPValidationError(
                        "Output %d: PSBT_OUT_SCRIPT does not match the derived "
                        "Silent Payment output" % out_idx
                    )
                scripts[out_idx] = script
        return scripts
