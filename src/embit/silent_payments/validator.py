"""
BIP-375 PSBT Validation

Implements the 4-stage validation pipeline for Silent Payments in PSBTs:
1. PSBT Structure - Verify BIP-375 field requirements
2. ECDH Coverage - Verify ECDH share presence and correctness
3. Input Eligibility - Verify input constraints with SP outputs
4. Output Scripts - Verify output scripts match SP derivation
"""

from .. import ec
from . import dleq
from .fields import SPValidationError
from .ecdh import get_eligible_inputs, input_public_key
from .bip352 import get_input_hash, derive_silent_payment_outputs
from ..transaction import SIGHASH, COutPoint
from ..script import Script
from ..util.secp256k1 import (
    ec_pubkey_combine,
    ec_pubkey_parse,
    ec_pubkey_serialize,
    ec_pubkey_tweak_mul,
    EC_COMPRESSED,
)


def _sum_pubkeys(pubkeys) -> bytes:
    """Sum a non-empty list of public keys, returning a 33-byte compressed point."""
    acc = ec_pubkey_parse(pubkeys[0].sec())
    for pk in pubkeys[1:]:
        acc = ec_pubkey_combine(acc, ec_pubkey_parse(pk.sec()))
    return ec_pubkey_serialize(acc, EC_COMPRESSED)


class BIP375Validator:
    """Validates PSBTs for BIP-375 compliance."""

    def __init__(self, psbt):
        """
        Args:
            psbt: A PSBTv2 instance to validate
        """
        self.psbt = psbt

    def has_sp_outputs(self) -> bool:
        """Check if PSBT has any SP outputs."""
        return any(out.sp_data is not None for out in self.psbt.outputs)

    def validate(self, skip_output_scripts: bool = False) -> bool:
        """
        Run full 4-stage validation pipeline.

        Args:
            skip_output_scripts: Skip stage 4 (output script validation) if True

        Returns:
            True if validation passes (otherwise raises).

        Raises:
            SPValidationError: With details of the first validation failure.
        """
        if self.psbt.version != 2:
            # SP fields only allowed in PSBTv2
            if self.has_sp_outputs():
                raise SPValidationError("SP fields only allowed in PSBTv2")
            return True

        # Stage 1: PSBT Structure
        try:
            self._validate_structure()
        except SPValidationError as e:
            raise SPValidationError("Structure validation failed: {}".format(e))

        if not self.has_sp_outputs():
            return True

        # Stage 2: ECDH Coverage
        try:
            self._validate_ecdh_coverage()
        except SPValidationError as e:
            raise SPValidationError("ECDH coverage validation failed: {}".format(e))

        # Stage 3: Input Eligibility
        try:
            self._validate_input_eligibility()
        except SPValidationError as e:
            raise SPValidationError("Input eligibility validation failed: {}".format(e))

        # Stage 4: Output Scripts (optional)
        if not skip_output_scripts:
            try:
                self._validate_output_scripts()
            except SPValidationError as e:
                raise SPValidationError("Output script validation failed: {}".format(e))

        return True

    def _validate_structure(self):
        """
        Stage 1: PSBT Structure validation.

        Checks:
        - SP fields only in outputs with PSBT_OUT_SP_V0_INFO
        - Field sizes are correct
        - Dependency relationships are valid
        - Modifiable flags when scripts are set
        """
        for i, out in enumerate(self.psbt.outputs):
            has_sp_info = out.sp_data is not None
            has_sp_label = out.sp_label is not None
            has_script = out.script_pubkey is not None

            # Label requires SP info
            if has_sp_label and not has_sp_info:
                raise SPValidationError(
                    "Output {}: PSBT_OUT_SP_V0_LABEL present without "
                    "PSBT_OUT_SP_V0_INFO".format(i)
                )

            # Either script or SP info must be present
            if not has_script and not has_sp_info:
                raise SPValidationError(
                    "Output {}: Must have either PSBT_OUT_SCRIPT or "
                    "PSBT_OUT_SP_V0_INFO".format(i)
                )

        # If any SP output has script set, modifiable flags must be 0
        if self.has_sp_outputs():
            for i, out in enumerate(self.psbt.outputs):
                if out.sp_data is not None and out.script_pubkey is not None:
                    # If script is set for SP output, modifiable flags must be 0
                    if (
                        self.psbt.tx_modifiable_flags is not None
                        and self.psbt.tx_modifiable_flags != 0
                    ):
                        raise SPValidationError(
                            "Output {}: PSBT_GLOBAL_TX_MODIFIABLE must be 0 when "
                            "PSBT_OUT_SCRIPT is set for SP output".format(i)
                        )

    def _validate_ecdh_coverage(self):
        """
        Stage 2: ECDH Coverage validation.

        For each SP output, verify:
        - All eligible inputs have ECDH shares or global share exists
        - DLEQ proofs exist and verify correctly
        - BIP32 derivations present when needed
        """
        eligible_inputs = get_eligible_inputs(self.psbt.inputs, has_sp_outputs=True)

        for out_idx, out in enumerate(self.psbt.outputs):
            if out.sp_data is None:
                continue  # Not an SP output

            scan_key = out.sp_data.scan_key
            scan_key_bytes = scan_key.sec()

            # Check if global ECDH share exists for this scan key
            has_global_share = scan_key_bytes in self.psbt.sp_ecdh_shares
            has_global_proof = scan_key_bytes in self.psbt.sp_dleq_proofs

            if has_global_share and not has_global_proof:
                raise SPValidationError(
                    "Output {}: PSBT_GLOBAL_SP_ECDH_SHARE present without "
                    "PSBT_GLOBAL_SP_DLEQ".format(out_idx)
                )

            if has_global_proof:
                # Verify global DLEQ proof
                if not out.script_pubkey:
                    # Can't verify without script (incomplete PSBT)
                    continue

                self._verify_global_dleq_proof(scan_key_bytes, out_idx, eligible_inputs)
            else:
                # Check per-input ECDH shares
                for inp_idx in eligible_inputs:
                    inp = self.psbt.inputs[inp_idx]

                    if scan_key_bytes not in inp.sp_ecdh_shares:
                        if out.script_pubkey:
                            # Script is set, all eligible inputs must have share
                            raise SPValidationError(
                                "Output {}: Input {} missing ECDH share for scan "
                                "key when output script is set".format(out_idx, inp_idx)
                            )
                        else:
                            # Incomplete PSBT - this is OK
                            continue

                    if scan_key_bytes not in inp.sp_dleq_proofs:
                        raise SPValidationError(
                            "Output {}: Input {} has ECDH share but missing DLEQ "
                            "proof".format(out_idx, inp_idx)
                        )

                    # Verify per-input DLEQ proof
                    if out.script_pubkey:  # Can verify only if complete
                        self._verify_input_dleq_proof(inp_idx, scan_key, out_idx)

                    # BIP-375: a per-input DLEQ proof requires
                    # PSBT_IN_BIP32_DERIVATION so verifiers can recover the input
                    # key. Taproot inputs are exempt — their key comes from the
                    # output key in the scriptPubKey, not a BIP-32 derivation.
                    if scan_key_bytes in inp.sp_dleq_proofs:
                        is_taproot = (
                            inp.script_pubkey is not None
                            and inp.script_pubkey.script_type() == "p2tr"
                        )
                        if not is_taproot and len(inp.bip32_derivations) == 0:
                            raise SPValidationError(
                                "Output {}: Input {} has DLEQ proof but missing "
                                "PSBT_IN_BIP32_DERIVATION".format(out_idx, inp_idx)
                            )

    def _verify_global_dleq_proof(
        self, scan_key_bytes: bytes, out_idx: int, eligible_inputs
    ):
        """Verify a global DLEQ proof."""
        scan_key = ec.PublicKey.parse(scan_key_bytes)
        proof_bytes = self.psbt.sp_dleq_proofs[scan_key_bytes]

        # Reconstruct sum of eligible input public keys
        eligible_pubkeys = []
        for inp_idx in eligible_inputs:
            inp = self.psbt.inputs[inp_idx]
            pubkey = self._get_input_public_key(inp, inp_idx)
            if pubkey:
                eligible_pubkeys.append(pubkey)

        if not eligible_pubkeys:
            raise SPValidationError(
                "Output {}: Cannot verify global DLEQ - no eligible inputs "
                "with public keys".format(out_idx)
            )

        A_sum_bytes = _sum_pubkeys(eligible_pubkeys)

        # Get ECDH share as public key
        ecdh_share = self.psbt.sp_ecdh_shares[scan_key_bytes]
        C = ec.PublicKey.parse(ecdh_share)

        # Verify proof
        if not dleq.verify_dleq_proof(
            A_sum_bytes, scan_key.sec(), C.sec(), proof_bytes
        ):
            raise SPValidationError(
                "Output {}: Global DLEQ proof verification failed".format(out_idx)
            )

    def _verify_input_dleq_proof(
        self, inp_idx: int, scan_key: ec.PublicKey, out_idx: int
    ):
        """Verify a per-input DLEQ proof."""
        inp = self.psbt.inputs[inp_idx]
        scan_key_bytes = scan_key.sec()

        # Get input's public key
        pubkey = self._get_input_public_key(inp, inp_idx)
        if not pubkey:
            # Can't verify without public key
            return

        # Get ECDH share
        ecdh_share = inp.sp_ecdh_shares[scan_key_bytes]
        C = ec.PublicKey.parse(ecdh_share)

        # Get proof
        proof_bytes = inp.sp_dleq_proofs[scan_key_bytes]

        # Verify
        if not dleq.verify_dleq_proof(
            pubkey.sec(), scan_key.sec(), C.sec(), proof_bytes
        ):
            raise SPValidationError(
                "Output {}: Per-input DLEQ proof verification failed "
                "for input {}".format(out_idx, inp_idx)
            )

    def _get_input_public_key(self, inp, inp_idx: int):
        """Return the input's public key used for SP shared-secret derivation."""
        return input_public_key(inp)

    def _validate_input_eligibility(self):
        """
        Stage 3: Input Eligibility validation.

        Checks:
        - No Segwit v>1 inputs with SP outputs
        - Only SIGHASH_ALL (if specified)
        """
        # Get eligible inputs - this will raise if Segwit v>1 found
        try:
            get_eligible_inputs(self.psbt.inputs, has_sp_outputs=True)
        except SPValidationError as e:
            raise SPValidationError("Invalid input for SP: {}".format(e))

        # Check sighash types
        for i, inp in enumerate(self.psbt.inputs):
            if inp.sighash_type is not None:
                # BIP-375: Only SIGHASH_ALL allowed with SP outputs
                if inp.sighash_type != SIGHASH.ALL:
                    raise SPValidationError(
                        "Input {}: Non-SIGHASH_ALL sighash type with SP outputs".format(
                            i
                        )
                    )

    def _validate_output_scripts(self):
        """
        Stage 4: Output Scripts validation.

        For each SP output:
        - Verify script is correctly derived from SP data and ECDH shares
        - Verify sorting of outputs by scan/spend keys
        """
        # Get eligible inputs
        eligible_inputs = get_eligible_inputs(self.psbt.inputs, has_sp_outputs=True)

        # Build outpoints and A_sum for input_hash (same for all scan-key groups).
        # BIP-352 input_hash commits to the smallest outpoint over ALL transaction
        # inputs (not just the eligible ones), while A is the sum of eligible keys.
        outpoints = [
            COutPoint(txid=self.psbt.tx.vin[i].txid, out_idx=self.psbt.tx.vin[i].vout)
            for i in range(len(self.psbt.inputs))
        ]
        eligible_pubkeys = [
            self._get_input_public_key(self.psbt.inputs[i], i) for i in eligible_inputs
        ]
        eligible_pubkeys = [pk for pk in eligible_pubkeys if pk is not None]
        if not eligible_pubkeys:
            raise SPValidationError(
                "Cannot validate output scripts: no eligible input public keys found"
            )
        A_sum_bytes = _sum_pubkeys(eligible_pubkeys)
        input_hash = get_input_hash(outpoints, A_sum_bytes)

        # Group SP outputs by scan key, preserving output-index order. The
        # derivation counter k is the output's position within its scan-key
        # group in this order (BIP-375: outputs are placed in the order that
        # determines k; outputs sharing scan+spend are ordered by output index).
        sp_outputs_by_scan = {}
        for out_idx, out in enumerate(self.psbt.outputs):
            if out.sp_data is not None:
                scan_key_bytes = out.sp_data.scan_key.sec()
                if scan_key_bytes not in sp_outputs_by_scan:
                    sp_outputs_by_scan[scan_key_bytes] = []
                sp_outputs_by_scan[scan_key_bytes].append((out_idx, out))

        # For each scan key, validate outputs
        for scan_key_bytes, outputs_for_scan in sp_outputs_by_scan.items():
            # Get ECDH share for this scan key
            ecdh_share = None
            if scan_key_bytes in self.psbt.sp_ecdh_shares:
                ecdh_share = self.psbt.sp_ecdh_shares[scan_key_bytes]
            else:
                # Sum per-input shares
                share_sum = None
                for inp_idx in eligible_inputs:
                    inp = self.psbt.inputs[inp_idx]
                    if scan_key_bytes in inp.sp_ecdh_shares:
                        share = ec_pubkey_parse(inp.sp_ecdh_shares[scan_key_bytes])
                        if share_sum is None:
                            share_sum = share
                        else:
                            share_sum = ec_pubkey_combine(share_sum, share)
                if share_sum is not None:
                    ecdh_share = ec_pubkey_serialize(share_sum, EC_COMPRESSED)

            if not ecdh_share:
                # Incomplete PSBT (output scripts not yet set) legitimately lacks
                # ECDH shares; only fail if a script is actually present to check.
                if any(out.script_pubkey is not None for _, out in outputs_for_scan):
                    raise SPValidationError(
                        "No ECDH share found for scan key in outputs"
                    )
                continue

            # Apply input_hash: adjusted_share = input_hash · ecdh_share (BIP-352)
            adjusted_handle = bytearray(ec_pubkey_parse(ecdh_share))
            ec_pubkey_tweak_mul(adjusted_handle, input_hash)
            adjusted_share = ec_pubkey_serialize(adjusted_handle, EC_COMPRESSED)

            derived = derive_silent_payment_outputs(
                adjusted_share,
                [
                    (out.sp_data.scan_key, out.sp_data.spend_key, out.sp_label)
                    for _, out in outputs_for_scan
                ],
            )

            # Validate each output's script against the derived key
            for pos, (out_idx, out) in enumerate(outputs_for_scan):
                if out.script_pubkey is None:
                    # Incomplete PSBT
                    continue

                expected_script = Script(b"\x51\x20" + derived[pos])
                if out.script_pubkey.serialize() != expected_script.serialize():
                    raise SPValidationError(
                        "Output {}: Script does not match derived "
                        "silent payment script".format(out_idx)
                    )


def validate_bip375_psbt(psbt, skip_output_scripts: bool = False) -> bool:
    """
    Validate a PSBT for BIP-375 compliance.

    Args:
        psbt: A PSBTv2 instance
        skip_output_scripts: Skip output script validation if True

    Returns:
        True if valid

    Raises:
        SPValidationError: With validation error details
    """
    validator = BIP375Validator(psbt)
    return validator.validate(skip_output_scripts=skip_output_scripts)
