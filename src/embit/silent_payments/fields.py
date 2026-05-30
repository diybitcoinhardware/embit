"""
BIP-375 Silent Payment shared types: exceptions and the SP output data class.

This is the dependency-root leaf of the silent_payments subpackage — the
exception types and SilentPaymentData are imported by ecdh, psbt, and
validator, so they live here to keep those modules free of import cycles.
"""

from .. import ec
from ..base import EmbitError


class SPFieldError(EmbitError):
    pass


class SPValidationError(EmbitError):
    pass


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
        except Exception as e:
            raise SPFieldError("Invalid SP data: {}".format(e))
