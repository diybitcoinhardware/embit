from io import BytesIO
from .. import bech32, ec
from ..misc import read_until
from .base import DescriptorBase
from .errors import DescriptorError
from .arguments import KeyOrigin, Key

SPSCAN_HRPS = {"spscan": "main", "tspscan": "test"}
SPSPEND_HRPS = {"spspend": "main", "tspspend": "test"}
SP_KEY_HRPS = {**SPSCAN_HRPS, **SPSPEND_HRPS}


def _bech32m_decode_sp_key(encoded):
    encoding, hrp, data = bech32.bech32_decode_long(encoded)
    if encoding is None:
        raise DescriptorError("Invalid bech32m encoding in SP key: %s" % encoded)
    if encoding != bech32.Encoding.BECH32M:
        raise DescriptorError("SP key must use bech32m encoding")
    if hrp not in SP_KEY_HRPS:
        raise DescriptorError("Unknown SP key HRP: %s" % hrp)
    if len(data) < 1:
        raise DescriptorError("SP key data too short")
    version = data[0]
    if version != 0:
        raise DescriptorError("Unsupported SP key version: %d" % version)
    payload = bech32.convertbits(data[1:], 5, 8, False)
    if payload is None:
        raise DescriptorError("Invalid SP key payload encoding")
    return hrp, bytes(payload)


def _bech32m_encode_sp_key(hrp, payload):
    data = bech32.convertbits(payload, 8, 5)
    return bech32.bech32_encode(bech32.Encoding.BECH32M, hrp, [0] + data)


class SPScanKey:
    """spscan key expression: encodes scan_privkey + spend_pubkey."""

    def __init__(self, scan_privkey, spend_pubkey, origin=None, network="main"):
        if not isinstance(scan_privkey, ec.PrivateKey):
            raise DescriptorError("SPScanKey scan key must be a PrivateKey")
        if not isinstance(spend_pubkey, ec.PublicKey):
            raise DescriptorError("SPScanKey spend key must be a PublicKey")
        self.scan_privkey = scan_privkey
        self.spend_pubkey = spend_pubkey
        self.origin = origin
        self.network = network

    @property
    def is_watch_only(self):
        return True

    @classmethod
    def decode(cls, encoded, origin=None):
        hrp, payload = _bech32m_decode_sp_key(encoded)
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
        hrp = "tspscan" if self.network == "test" else "spscan"
        payload = self.scan_privkey.secret + self.spend_pubkey.sec()
        return _bech32m_encode_sp_key(hrp, payload)

    def __str__(self):
        prefix = "[%s]" % self.origin if self.origin else ""
        return prefix + self.encode()


class SPSpendKey:
    """spspend key expression: encodes scan_privkey + spend_privkey."""

    def __init__(self, scan_privkey, spend_privkey, origin=None, network="main"):
        if not isinstance(scan_privkey, ec.PrivateKey):
            raise DescriptorError("SPSpendKey scan key must be a PrivateKey")
        if not isinstance(spend_privkey, ec.PrivateKey):
            raise DescriptorError("SPSpendKey spend key must be a PrivateKey")
        self.scan_privkey = scan_privkey
        self.spend_privkey = spend_privkey
        self.origin = origin
        self.network = network

    @property
    def spend_pubkey(self):
        return self.spend_privkey.get_public_key()

    @property
    def is_watch_only(self):
        return False

    @classmethod
    def decode(cls, encoded, origin=None):
        hrp, payload = _bech32m_decode_sp_key(encoded)
        if hrp not in SPSPEND_HRPS:
            raise DescriptorError("Expected spspend HRP, got: %s" % hrp)
        if len(payload) != 64:
            raise DescriptorError(
                "spspend payload must be 64 bytes (32 + 32), got %d" % len(payload)
            )
        scan_privkey = ec.PrivateKey(payload[:32])
        spend_privkey = ec.PrivateKey(payload[32:64])
        network = SPSPEND_HRPS[hrp]
        return cls(scan_privkey, spend_privkey, origin, network)

    def encode(self):
        hrp = "tspspend" if self.network == "test" else "spspend"
        payload = self.scan_privkey.secret + self.spend_privkey.secret
        return _bech32m_encode_sp_key(hrp, payload)

    def __str__(self):
        prefix = "[%s]" % self.origin if self.origin else ""
        return prefix + self.encode()


def _read_sp_key_expression(s):
    """Read an spscan/spspend expression or a standard Key from stream."""
    first = s.read(1)
    origin = None
    if first == b"[":
        prefix, char = read_until(s, b"]")
        if char != b"]":
            raise DescriptorError("Invalid key - missing ]")
        origin = KeyOrigin.from_string(prefix.decode())
    else:
        s.seek(-1, 1)

    pos_before = s.tell()
    token, char = read_until(s, b",)")
    if char is not None:
        s.seek(-1, 1)
    token_str = token.decode()

    lower = token_str.lower()
    for hrp in SPSCAN_HRPS:
        if lower.startswith(hrp + "1"):
            return SPScanKey.decode(token_str, origin), char
    for hrp in SPSPEND_HRPS:
        if lower.startswith(hrp + "1"):
            return SPSpendKey.decode(token_str, origin), char

    s.seek(pos_before)
    if origin:
        origin_str = "[%s]" % origin
        combined = BytesIO(origin_str.encode() + s.read())
        key = Key.read_from(combined)
    else:
        key = Key.read_from(s)
    return key, None


class SilentPaymentDescriptor(DescriptorBase):
    """BIP-392 sp() descriptor for Silent Payments."""

    def __init__(self, sp_key=None, scan_key=None, spend_key=None):
        if sp_key is not None:
            if not isinstance(sp_key, (SPScanKey, SPSpendKey)):
                raise DescriptorError(
                    "Single-arg sp() requires an spscan or spspend key expression"
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
        if "#" in desc:
            desc = desc.split("#")[0]
        s = BytesIO(desc.encode())
        start = s.read(3)
        if start != b"sp(":
            raise DescriptorError("Expected sp( prefix, got: %s" % start.decode())
        res = cls._read_args(s)
        end = s.read(1)
        if end != b")":
            raise DescriptorError("Expected closing ) for sp()")
        left = s.read()
        if len(left) > 0:
            raise DescriptorError("Unexpected characters after sp(): %r" % left)
        return res

    @classmethod
    def read_from(cls, s):
        return cls._read_args(s)

    @classmethod
    def _read_args(cls, s):
        first_arg, sep = _read_sp_key_expression(s)

        if isinstance(first_arg, (SPScanKey, SPSpendKey)):
            c = s.read(1)
            if c == b")":
                s.seek(-1, 1)
                return cls(sp_key=first_arg)
            raise DescriptorError(
                "spscan/spspend key must be the only argument to sp()"
            )

        c = s.read(1)
        if c != b",":
            raise DescriptorError(
                "Single-arg sp() requires spscan or spspend key expression, "
                "got a standard key"
            )

        scan_key = first_arg
        if not _is_private_key(scan_key):
            raise DescriptorError("Two-arg sp(): scan key must be private")
        if isinstance(scan_key.key, ec.PrivateKey) and not scan_key.key.compressed:
            raise DescriptorError("Uncompressed keys are not allowed in sp()")

        spend_arg, _ = _read_sp_key_expression(s)
        if isinstance(spend_arg, (SPScanKey, SPSpendKey)):
            raise DescriptorError(
                "Two-arg sp() cannot use spscan/spspend key expressions"
            )
        if isinstance(spend_arg, Key) and isinstance(spend_arg.key, ec.PrivateKey):
            if not spend_arg.key.compressed:
                raise DescriptorError("Uncompressed keys are not allowed in sp()")

        return cls(scan_key=scan_key, spend_key=spend_arg)

    def to_string(self):
        if self.sp_key is not None:
            return "sp(%s)" % self.sp_key
        return "sp(%s,%s)" % (self.scan_key, self.spend_key)

    def __str__(self):
        return self.to_string()

    def __repr__(self):
        return self.to_string()


def _is_private_key(key):
    if isinstance(key, Key):
        return key.is_private
    return False
