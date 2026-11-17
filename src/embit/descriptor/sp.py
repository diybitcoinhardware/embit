from io import BytesIO
from .. import bech32, ec
from ..misc import read_until
from .base import DescriptorBase
from .errors import DescriptorError
from .arguments import KeyOrigin, Key

# BIP-392 only has a mainnet and a testnet HRP, regtest shares "tspscan"
# (same as Sparrow). Keyed like embit.networks.NETWORKS.
SPSCAN_NETWORK_HRPS = {
    "main": "spscan",
    "test": "tspscan",
    "signet": "tspscan",
    "regtest": "tspscan",
}
SPSCAN_HRPS = {"spscan": "main", "tspscan": "test"}


class SPScanKey:
    """spscan key expression: encodes scan_privkey + spend_pubkey."""

    def __init__(self, scan_privkey, spend_pubkey, origin=None, network="main"):
        if not isinstance(scan_privkey, ec.PrivateKey):
            raise DescriptorError("SPScanKey scan key must be a PrivateKey")
        if not isinstance(spend_pubkey, ec.PublicKey):
            raise DescriptorError("SPScanKey spend key must be a PublicKey")
        # a NETWORKS dict is unhashable, so check the type before the lookup
        if not isinstance(network, str) or network not in SPSCAN_NETWORK_HRPS:
            raise DescriptorError(
                "Unknown network %r, expected one of %s"
                % (network, list(SPSCAN_NETWORK_HRPS))
            )
        self.scan_privkey = scan_privkey
        self.spend_pubkey = spend_pubkey
        self.origin = origin
        self.network = network

    @property
    def is_watch_only(self):
        return True

    # The spend key is public only, so an spscan key can never sign. PSBT
    # signing (resolve_signing_root) skips keys that report is_private False.
    is_private = False

    @classmethod
    def decode(cls, encoded, origin=None):
        try:
            hrp, version, payload = bech32.bech32m_decode_versioned(encoded)
        except bech32.Bech32DecodeError as e:
            raise DescriptorError("Invalid silent payment key: %s" % e)
        if version != 0:
            raise DescriptorError(
                "Unsupported silent payment key version: %d" % version
            )
        if hrp not in SPSCAN_HRPS:
            raise DescriptorError("Expected spscan HRP, got: %s" % hrp)
        if len(payload) != 65:
            raise DescriptorError(
                "spscan payload must be 65 bytes (32 privkey + 33 pubkey), got %d"
                % len(payload)
            )
        scan_privkey = ec.PrivateKey(payload[:32])
        spend_pubkey = ec.PublicKey.parse(payload[32:65])
        network = SPSCAN_HRPS[hrp]
        return cls(scan_privkey, spend_pubkey, origin, network)

    def encode(self):
        hrp = SPSCAN_NETWORK_HRPS[self.network]
        payload = self.scan_privkey.secret + self.spend_pubkey.sec()
        return bech32.bech32m_encode_versioned(hrp, 0, payload)

    def __str__(self):
        prefix = "[%s]" % self.origin if self.origin else ""
        return prefix + self.encode()


def _read_sp_key_expression(s):
    """Read an spscan expression or a standard Key from stream."""
    first = s.read(1)
    if not first:
        # nothing left; the seek(-1, 1) below would rewind onto the previous char
        raise DescriptorError("Empty key expression in sp()")
    origin = None
    origin_len = 0
    if first == b"[":
        prefix, char = read_until(s, b"]")
        if char != b"]":
            raise DescriptorError("Invalid key - missing ]")
        origin = KeyOrigin.from_string(prefix.decode())
        origin_len = len(prefix) + 2  # '[' + prefix + ']'
    else:
        s.seek(-1, 1)

    token, char = read_until(s, b",)")
    if char is not None:
        s.seek(-1, 1)
    token_str = token.decode()

    if not token_str:
        raise DescriptorError("Empty key expression in sp()")

    lower = token_str.lower()
    for hrp in SPSCAN_HRPS:
        if lower.startswith(hrp + "1"):
            return SPScanKey.decode(token_str, origin)

    # Not a silent-payment key: rewind past the origin prefix and token (no
    # tell(); MicroPython's BytesIO lacks it) and let Key.read_from(s) consume
    # the expression in-place, leaving the stream at the delimiter for the caller.
    s.seek(-(origin_len + len(token)), 1)
    return Key.read_from(s)


class SilentPaymentDescriptor(DescriptorBase):
    """BIP-392 sp() descriptor for Silent Payments."""

    def __init__(self, sp_key=None, scan_key=None, spend_key=None):
        if sp_key is not None:
            if not isinstance(sp_key, SPScanKey):
                raise DescriptorError(
                    "Single-arg sp() requires an spscan key expression"
                )
            self.sp_key = sp_key
            self.scan_key = None
            self.spend_key = None
        elif scan_key is not None:
            if not _is_private_key(scan_key):
                raise DescriptorError("Two-arg sp(): scan key must be private")
            self.sp_key = None
            self.scan_key = scan_key
            self.spend_key = spend_key
        else:
            raise DescriptorError("sp() requires at least one argument")

    @property
    def is_single_arg(self):
        return self.sp_key is not None

    @property
    def is_watch_only(self):
        if self.sp_key is not None:
            return self.sp_key.is_watch_only
        return not _is_private_key(self.spend_key)

    @property
    def keys(self):
        if self.sp_key is not None:
            return [self.sp_key]
        return [self.scan_key, self.spend_key]

    def get_scan_privkey(self):
        if self.sp_key is not None:
            return self.sp_key.scan_privkey
        k = self.scan_key
        if isinstance(k, Key):
            return k.private_key
        return None

    def get_spend_pubkey(self):
        if self.sp_key is not None:
            return self.sp_key.spend_pubkey
        k = self.spend_key
        if isinstance(k, Key):
            return k.get_public_key()
        return None

    @classmethod
    def from_string(cls, desc):
        s = BytesIO(desc.encode())
        res = cls.read_from(s)
        left = s.read()
        # a trailing #checksum is not verified, same as Descriptor.from_string
        if len(left) > 0 and not left.startswith(b"#"):
            raise DescriptorError("Unexpected characters after sp(): %r" % left)
        return res

    @classmethod
    def read_from(cls, s):
        start = s.read(3)
        if start != b"sp(":
            raise DescriptorError("Expected sp( prefix, got: %r" % start)
        res = cls._read_args(s)
        if s.read(1) != b")":
            raise DescriptorError("Expected closing ) for sp()")
        return res

    @classmethod
    def _read_args(cls, s):
        first_arg = _read_sp_key_expression(s)

        if isinstance(first_arg, SPScanKey):
            c = s.read(1)
            if c == b")":
                s.seek(-1, 1)
                return cls(sp_key=first_arg)
            raise DescriptorError("spscan key must be the only argument to sp()")

        c = s.read(1)
        if c != b",":
            raise DescriptorError(
                "Single-arg sp() requires an spscan key expression, "
                "got a standard key"
            )

        scan_key = first_arg
        if not _is_private_key(scan_key):
            raise DescriptorError("Two-arg sp(): scan key must be private")
        if isinstance(scan_key.key, ec.PrivateKey) and not scan_key.key.compressed:
            raise DescriptorError("Uncompressed keys are not allowed in sp()")

        spend_arg = _read_sp_key_expression(s)
        if isinstance(spend_arg, SPScanKey):
            raise DescriptorError("Two-arg sp() cannot use spscan key expressions")
        if isinstance(spend_arg, Key) and isinstance(spend_arg.key, ec.PrivateKey):
            if not spend_arg.key.compressed:
                raise DescriptorError("Uncompressed keys are not allowed in sp()")

        return cls(scan_key=scan_key, spend_key=spend_arg)

    def derive(self, *args, **kwargs):
        raise DescriptorError(
            "sp() descriptors do not support derive(); see BIP-352 for output derivation"
        )

    def script_pubkey(self, *args, **kwargs):
        raise DescriptorError(
            "sp() descriptors have no fixed script_pubkey(); outputs are derived per BIP-352"
        )

    def address(self, *args, **kwargs):
        raise DescriptorError(
            "sp() descriptors have no address(); use BIP-352 silent payment address generation"
        )

    def to_string(self):
        if self.sp_key is not None:
            return "sp(%s)" % self.sp_key
        return "sp(%s,%s)" % (self.scan_key, self.spend_key)

    def write_to(self, stream, *args, **kwargs):
        # serialize(), == and hash() all go through write_to
        return stream.write(self.to_string().encode())

    def __repr__(self):
        return self.to_string()


def _is_private_key(key):
    if isinstance(key, Key):
        return key.is_private
    return False
