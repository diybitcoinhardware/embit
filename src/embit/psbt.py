from collections import OrderedDict
from .transaction import (
    Transaction,
    TransactionOutput,
    TransactionInput,
    SIGHASH,
    _signed_from_bytes,
    _signed_to_bytes,
)
from . import compact
from . import bip32
from . import ec
from . import hashes
from . import script
from .script import Script, Witness
from .base import EmbitBase, EmbitError

from binascii import b2a_base64, a2b_base64, hexlify, unhexlify
from io import BytesIO

LOCKTIME_THRESHOLD = 500000000


class PSBTError(EmbitError):
    pass


class CompressMode:
    KEEP_ALL = 0
    CLEAR_ALL = 1
    PARTIAL = 2


def ser_string(stream, s: bytes) -> int:
    return stream.write(compact.to_bytes(len(s))) + stream.write(s)


def read_string(stream) -> bytes:
    l = compact.read_from(stream)
    s = stream.read(l)
    if len(s) != l:
        raise PSBTError("Failed to read %d bytes" % l)
    return s


def skip_string(stream) -> int:
    l = compact.read_from(stream)
    stream.seek(l, 1)
    return len(compact.to_bytes(l)) + l


class DerivationPath(EmbitBase):
    def __init__(self, fingerprint: bytes, derivation: list):
        self.fingerprint = fingerprint
        self.derivation = derivation

    def write_to(self, stream) -> int:
        r = stream.write(self.fingerprint)
        for idx in self.derivation:
            r += stream.write(idx.to_bytes(4, "little"))
        return r

    @classmethod
    def read_from(cls, stream):
        fingerprint = stream.read(4)
        derivation = []
        while True:
            r = stream.read(4)
            if len(r) == 0:
                break
            if len(r) < 4:
                raise PSBTError("Invalid length")
            derivation.append(int.from_bytes(r, "little"))
        return cls(fingerprint, derivation)


class PSBTScope(EmbitBase):
    def __init__(self, unknown: dict = {}):
        self.unknown = unknown
        self.parse_unknowns()

    def write_to(self, stream, skip_separator=False, **kwargs) -> int:
        # unknown
        r = 0
        for key in self.unknown:
            r += ser_string(stream, key)
            r += ser_string(stream, self.unknown[key])
        # separator
        if not skip_separator:
            r += stream.write(b"\x00")
        return r

    def parse_unknowns(self):
        # go through all the unknowns and parse them
        for k in list(self.unknown):
            s = BytesIO()
            ser_string(s, self.unknown[k])
            s.seek(0)
            self.read_value(s, k)

    def read_value(self, stream, key, version=None):
        # separator
        if len(key) == 0:
            return
        value = read_string(stream)
        if key in self.unknown:
            raise PSBTError("Duplicated key")
        self.unknown[key] = value

    def update(self, other):
        self.unknown.update(other.unknown)

    @classmethod
    def read_from(cls, stream, *args, **kwargs):
        res = cls({}, *args, **kwargs)
        while True:
            key = read_string(stream)
            # separator
            if len(key) == 0:
                break
            res.read_value(stream, key)
        return res


class InputScope(PSBTScope):
    TX_CLS = Transaction
    TXOUT_CLS = TransactionOutput

    def __init__(self, unknown: dict = {}, vin=None, compress=CompressMode.KEEP_ALL):
        self.compress = compress
        self.txid = None
        self.vout = None
        self.sequence = None
        if vin is not None:
            self.txid = vin.txid
            self.vout = vin.vout
            self.sequence = vin.sequence
        self.unknown = unknown
        self.non_witness_utxo = None
        self.witness_utxo = None
        self._utxo = None
        self._txhash = None
        self._verified = False
        self.partial_sigs = OrderedDict()
        self.sighash_type = None
        self.redeem_script = None
        self.witness_script = None
        self.bip32_derivations = OrderedDict()

        # tuples of ([leaf_hashes], DerivationPath)
        self.taproot_bip32_derivations = OrderedDict()
        self.taproot_internal_key = None
        self.taproot_merkle_root = None
        self.taproot_key_sig = None
        self.taproot_sigs = OrderedDict()
        self.taproot_scripts = OrderedDict()

        self.final_scriptsig = None
        self.final_scriptwitness = None
        self.required_time_locktime = None
        self.required_height_locktime = None
        self.parse_unknowns()

    def clear_metadata(self, compress=CompressMode.CLEAR_ALL):
        """Removes metadata like derivations, utxos etc except final or partial sigs"""
        if compress == CompressMode.KEEP_ALL:
            return
        self.unknown = {}
        if compress == CompressMode.CLEAR_ALL:
            self.non_witness_utxo = None
            self.witness_utxo = None
            self.sighash_type = None
            self.redeem_script = None
            self.witness_script = None
        else:
            if self.witness_utxo is not None:
                self.non_witness_utxo = None
        self.bip32_derivations = OrderedDict()
        self.taproot_bip32_derivations = OrderedDict()
        self.taproot_internal_key = None
        self.taproot_merkle_root = None
        self.taproot_scripts = OrderedDict()

    def update(self, other):
        self.txid = other.txid or self.txid
        self.vout = other.vout if other.vout is not None else self.vout
        self.sequence = other.sequence if other.sequence is not None else self.sequence
        self.unknown.update(other.unknown)
        self.non_witness_utxo = other.non_witness_utxo or self.non_witness_utxo
        self.witness_utxo = other.witness_utxo or self.witness_utxo
        self._utxo = other._utxo or self._utxo
        self.partial_sigs.update(other.partial_sigs)
        self.sighash_type = (
            other.sighash_type if other.sighash_type is not None else self.sighash_type
        )
        self.redeem_script = other.redeem_script or self.redeem_script
        self.witness_script = other.witness_script or self.witness_script
        self.bip32_derivations.update(other.bip32_derivations)
        self.taproot_bip32_derivations.update(other.taproot_bip32_derivations)
        self.taproot_internal_key = other.taproot_internal_key
        self.taproot_merkle_root = other.taproot_merkle_root or self.taproot_merkle_root
        self.taproot_key_sig = other.taproot_key_sig or self.taproot_key_sig
        self.taproot_sigs.update(other.taproot_sigs)
        self.taproot_scripts.update(other.taproot_scripts)
        self.final_scriptsig = other.final_scriptsig or self.final_scriptsig
        self.final_scriptwitness = other.final_scriptwitness or self.final_scriptwitness
        self.required_time_locktime = (
            other.required_time_locktime
            if other.required_time_locktime is not None
            else self.required_time_locktime
        )
        self.required_height_locktime = (
            other.required_height_locktime
            if other.required_height_locktime is not None
            else self.required_height_locktime
        )

    @property
    def vin(self):
        return TransactionInput(
            self.txid,
            self.vout,
            sequence=(self.sequence if self.sequence is not None else 0xFFFFFFFF),
        )

    @property
    def utxo(self):
        return (
            self._utxo
            or self.witness_utxo
            or (
                self.non_witness_utxo.vout[self.vout] if self.non_witness_utxo else None
            )
        )

    @property
    def script_pubkey(self):
        return self.utxo.script_pubkey if self.utxo else None

    @property
    def is_verified(self):
        """Check if prev txid was verified using non_witness_utxo. See `verify()`"""
        return self._verified

    @property
    def is_taproot(self):
        return self.utxo.script_pubkey.script_type() == "p2tr"

    def verify(self, ignore_missing=False):
        """Verifies the hash of previous transaction provided in non_witness_utxo.
        We must verify on a hardware wallet even on segwit transactions to avoid
        miner fee attack described here:
        https://blog.trezor.io/details-of-firmware-updates-for-trezor-one-version-1-9-1-and-trezor-model-t-version-2-3-1-1eba8f60f2dd
        For legacy txs we need to verify it to calculate fee.
        """
        if self.non_witness_utxo or self._txhash:
            txid = (
                bytes(reversed(self._txhash))
                if self._txhash
                else self.non_witness_utxo.txid()
            )
            if self.txid == txid:
                self._verified = True
                return True
            else:
                raise PSBTError("Previous txid doesn't match non_witness_utxo txid")
        if not ignore_missing:
            raise PSBTError("Missing non_witness_utxo")
        return False

    def read_value(self, stream, k, version=None):
        # separator
        if len(k) == 0:
            return
        # non witness utxo, can be parsed and verified without too much memory
        if k[0] == 0x00:
            if len(k) != 1:
                raise PSBTError("Invalid non-witness utxo key")
            elif self.non_witness_utxo is not None:
                raise PSBTError("Duplicated utxo value")
            else:
                compact.read_from(stream)
                # For PSBTv2, PSBT_IN_OUTPUT_INDEX may follow PSBT_IN_NON_WITNESS_UTXO;
                # use the pre-scanned vout (set by read_from) when the field hasn't
                # been parsed yet so the OOM protection is key-order independent.
                effective_vout = (
                    self.vout
                    if self.vout is not None
                    else getattr(self, "_prescan_vout", None)
                )
                # we verified and saved utxo
                if self.compress and effective_vout is not None:
                    txout, txhash = self.TX_CLS.read_vout(stream, effective_vout)
                    self._txhash = txhash
                    self._utxo = txout
                else:
                    tx = self.TX_CLS.read_from(stream)
                    self.non_witness_utxo = tx
            return

        v = read_string(stream)

        # witness utxo
        if k[0] == 0x01:
            if len(k) != 1:
                raise PSBTError("Invalid witness utxo key")
            elif self.witness_utxo is not None:
                raise PSBTError("Duplicated utxo value")
            else:
                self.witness_utxo = self.TXOUT_CLS.parse(v)
        # partial signature
        elif k[0] == 0x02:
            # we don't need this key for signing
            if self.compress:
                return
            pub = ec.PublicKey.parse(k[1:])
            if pub in self.partial_sigs:
                raise PSBTError("Duplicated partial sig")
            else:
                self.partial_sigs[pub] = v
        # hash type
        elif k[0] == 0x03:
            if len(k) != 1:
                raise PSBTError("Invalid sighash type key")
            elif self.sighash_type is None:
                if len(v) != 4:
                    raise PSBTError("Sighash type should be 4 bytes long")
                self.sighash_type = int.from_bytes(v, "little")
            else:
                raise PSBTError("Duplicated sighash type")
        # redeem script
        elif k[0] == 0x04:
            if len(k) != 1:
                raise PSBTError("Invalid redeem script key")
            elif self.redeem_script is None:
                self.redeem_script = Script(v)
            else:
                raise PSBTError("Duplicated redeem script")
        # witness script
        elif k[0] == 0x05:
            if len(k) != 1:
                raise PSBTError("Invalid witness script key")
            elif self.witness_script is None:
                self.witness_script = Script(v)
            else:
                raise PSBTError("Duplicated witness script")

        # PSBT_IN_BIP32_DERIVATION
        elif k[0] == 0x06:
            pub = ec.PublicKey.parse(k[1:])
            if pub in self.bip32_derivations:
                raise PSBTError("Duplicated derivation path")
            else:
                self.bip32_derivations[pub] = DerivationPath.parse(v)

        # final scriptsig
        elif k[0] == 0x07:
            # we don't need this key for signing
            if self.compress:
                return
            if len(k) != 1:
                raise PSBTError("Invalid final scriptsig key")
            elif self.final_scriptsig is None:
                self.final_scriptsig = Script(v)
            else:
                raise PSBTError("Duplicated final scriptsig")
        # final script witness
        elif k[0] == 0x08:
            # we don't need this key for signing
            if self.compress:
                return
            if len(k) != 1:
                raise PSBTError("Invalid final scriptwitness key")
            elif self.final_scriptwitness is None:
                self.final_scriptwitness = Witness.parse(v)
            else:
                raise PSBTError("Duplicated final scriptwitness")

        # PSBTv2 fields
        elif k == b"\x0e":
            if version != 2:
                raise PSBTError("PSBT_IN_PREVIOUS_TXID not allowed in PSBTv0")
            if len(v) != 32:
                raise PSBTError("PSBT_IN_PREVIOUS_TXID must be 32 bytes")
            if self.txid is not None:
                raise PSBTError("Duplicated PSBT_IN_PREVIOUS_TXID")
            self.txid = bytes(reversed(v))
        elif k == b"\x0f":
            if version != 2:
                raise PSBTError("PSBT_IN_OUTPUT_INDEX not allowed in PSBTv0")
            if len(v) != 4:
                raise PSBTError("PSBT_IN_OUTPUT_INDEX must be 4 bytes")
            if self.vout is not None:
                raise PSBTError("Duplicated PSBT_IN_OUTPUT_INDEX")
            self.vout = int.from_bytes(v, "little")
        elif k == b"\x10":
            if version != 2:
                raise PSBTError("PSBT_IN_SEQUENCE not allowed in PSBTv0")
            if len(v) != 4:
                raise PSBTError("PSBT_IN_SEQUENCE must be 4 bytes")
            if self.sequence is not None:
                raise PSBTError("Duplicated PSBT_IN_SEQUENCE")
            self.sequence = int.from_bytes(v, "little")

        # PSBT_IN_REQUIRED_TIME_LOCKTIME
        elif k == b"\x11":
            if version != 2:
                raise PSBTError("PSBT_IN_REQUIRED_TIME_LOCKTIME not allowed in PSBTv0")
            if self.required_time_locktime is not None:
                raise PSBTError("Duplicated required time locktime")
            if len(v) != 4:
                raise PSBTError("PSBT_IN_REQUIRED_TIME_LOCKTIME must be 4 bytes")
            locktime = int.from_bytes(v, "little")
            if locktime < LOCKTIME_THRESHOLD:
                raise PSBTError(
                    "Time-based locktime must be >= %d" % LOCKTIME_THRESHOLD
                )
            self.required_time_locktime = locktime

        # PSBT_IN_REQUIRED_HEIGHT_LOCKTIME
        elif k == b"\x12":
            if version != 2:
                raise PSBTError(
                    "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME not allowed in PSBTv0"
                )
            if self.required_height_locktime is not None:
                raise PSBTError("Duplicated required height locktime")
            if len(v) != 4:
                raise PSBTError("PSBT_IN_REQUIRED_HEIGHT_LOCKTIME must be 4 bytes")
            locktime = int.from_bytes(v, "little")
            if locktime >= LOCKTIME_THRESHOLD or locktime == 0:
                raise PSBTError(
                    "Height-based locktime must be > 0 and < %d"
                    % LOCKTIME_THRESHOLD
                )
            self.required_height_locktime = locktime

        # PSBT_IN_TAP_KEY_SIG
        elif k[0] == 0x13:
            # read the taproot key sig
            if len(k) != 1:
                raise PSBTError("Invalid taproot key signature key")
            if self.taproot_key_sig is not None:
                raise PSBTError("Duplicated taproot key signature")
            self.taproot_key_sig = v

        # PSBT_IN_TAP_SCRIPT_SIG
        elif k[0] == 0x14:
            if len(k) != 65:
                raise PSBTError("Invalid key length")
            pub = ec.PublicKey.from_xonly(k[1:33])
            leaf = k[33:]
            if (pub, leaf) in self.taproot_sigs:
                raise PSBTError("Duplicated taproot sig")
            self.taproot_sigs[(pub, leaf)] = v

        # PSBT_IN_TAP_LEAF_SCRIPT
        elif k[0] == 0x15:
            control_block = k[1:]
            if control_block in self.taproot_scripts:
                raise PSBTError("Duplicated taproot script")
            self.taproot_scripts[control_block] = v

        # PSBT_IN_TAP_BIP32_DERIVATION
        elif k[0] == 0x16:
            pub = ec.PublicKey.from_xonly(k[1:])
            if pub not in self.taproot_bip32_derivations:
                b = BytesIO(v)
                num_leaf_hashes = compact.read_from(b)
                leaf_hashes = [b.read(32) for i in range(num_leaf_hashes)]
                if not all([len(leaf) == 32 for leaf in leaf_hashes]):
                    raise PSBTError("Invalid length of taproot leaf hashes")
                der = DerivationPath.read_from(b)
                self.taproot_bip32_derivations[pub] = (leaf_hashes, der)

        # PSBT_IN_TAP_INTERNAL_KEY
        elif k[0] == 0x17:
            self.taproot_internal_key = ec.PublicKey.from_xonly(v)

        # PSBT_IN_TAP_MERKLE_ROOT
        elif k[0] == 0x18:
            self.taproot_merkle_root = v

        else:
            if k in self.unknown:
                raise PSBTError("Duplicated key")
            self.unknown[k] = v

    def write_to(self, stream, skip_separator=False, version=None, **kwargs) -> int:
        r = 0
        if self.non_witness_utxo is not None:
            r += stream.write(b"\x01\x00")
            r += ser_string(stream, self.non_witness_utxo.serialize())
        if self.witness_utxo is not None:
            r += stream.write(b"\x01\x01")
            r += ser_string(stream, self.witness_utxo.serialize())
        for pub in self.partial_sigs:
            r += ser_string(stream, b"\x02" + pub.serialize())
            r += ser_string(stream, self.partial_sigs[pub])
        if self.sighash_type is not None:
            r += stream.write(b"\x01\x03")
            r += ser_string(stream, self.sighash_type.to_bytes(4, "little"))
        if self.redeem_script is not None:
            r += stream.write(b"\x01\x04")
            r += self.redeem_script.write_to(stream)  # script serialization has length
        if self.witness_script is not None:
            r += stream.write(b"\x01\x05")
            r += self.witness_script.write_to(stream)  # script serialization has length
        for pub in self.bip32_derivations:
            r += ser_string(stream, b"\x06" + pub.serialize())
            r += ser_string(stream, self.bip32_derivations[pub].serialize())
        if self.final_scriptsig is not None:
            r += stream.write(b"\x01\x07")
            r += self.final_scriptsig.write_to(stream)
        if self.final_scriptwitness is not None:
            r += stream.write(b"\x01\x08")
            r += ser_string(stream, self.final_scriptwitness.serialize())

        if version == 2:
            if self.txid is not None:
                r += ser_string(stream, b"\x0e")
                r += ser_string(stream, bytes(reversed(self.txid)))
            if self.vout is not None:
                r += ser_string(stream, b"\x0f")
                r += ser_string(stream, self.vout.to_bytes(4, "little"))
            if self.sequence is not None:
                r += ser_string(stream, b"\x10")
                r += ser_string(stream, self.sequence.to_bytes(4, "little"))

            # Add required time locktime if present
            if self.required_time_locktime is not None:
                r += ser_string(stream, b"\x11")
                r += ser_string(
                    stream, self.required_time_locktime.to_bytes(4, "little")
                )

            # Add required height locktime if present
            if self.required_height_locktime is not None:
                r += ser_string(stream, b"\x12")
                r += ser_string(
                    stream, self.required_height_locktime.to_bytes(4, "little")
                )

        # PSBT_IN_TAP_KEY_SIG
        if self.taproot_key_sig is not None:
            r += ser_string(stream, b"\x13")
            r += ser_string(stream, self.taproot_key_sig)

        # PSBT_IN_TAP_SCRIPT_SIG
        for pub, leaf in self.taproot_sigs:
            r += ser_string(stream, b"\x14" + pub.xonly() + leaf)
            r += ser_string(stream, self.taproot_sigs[(pub, leaf)])

        # PSBT_IN_TAP_LEAF_SCRIPT
        for control_block in self.taproot_scripts:
            r += ser_string(stream, b"\x15" + control_block)
            r += ser_string(stream, self.taproot_scripts[control_block])

        # PSBT_IN_TAP_BIP32_DERIVATION
        for pub in self.taproot_bip32_derivations:
            r += ser_string(stream, b"\x16" + pub.xonly())
            leaf_hashes, derivation = self.taproot_bip32_derivations[pub]
            r += ser_string(
                stream,
                compact.to_bytes(len(leaf_hashes))
                + b"".join(leaf_hashes)
                + derivation.serialize(),
            )

        # PSBT_IN_TAP_INTERNAL_KEY
        if self.taproot_internal_key is not None:
            r += ser_string(stream, b"\x17")
            r += ser_string(stream, self.taproot_internal_key.xonly())

        # PSBT_IN_TAP_MERKLE_ROOT
        if self.taproot_merkle_root is not None:
            r += ser_string(stream, b"\x18")
            r += ser_string(stream, self.taproot_merkle_root)

        # unknown
        for key in self.unknown:
            r += ser_string(stream, key)
            r += ser_string(stream, self.unknown[key])
        # separator
        if not skip_separator:
            r += stream.write(b"\x00")
        return r

    @classmethod
    def read_from(cls, stream, compress=CompressMode.KEEP_ALL, vin=None, version=None):
        res = cls({}, vin=vin, compress=compress)
        # PSBT maps are unordered, so PSBTv2 input maps may provide the output
        # index after the non-witness UTXO. Peek only at compact-sized keys and
        # skip values to keep compressed parsing independent of key order.
        res._prescan_vout = None
        if version == 2 and compress and res.vout is None:
            try:
                start_pos = stream.tell()
                while True:
                    k = read_string(stream)
                    if len(k) == 0:
                        break
                    if k == b"\x0f":
                        v = read_string(stream)
                        if len(v) == 4:
                            res._prescan_vout = int.from_bytes(v, "little")
                        else:
                            # Let the real parse raise the precise validation error.
                            pass
                        break
                    skip_string(stream)
                stream.seek(start_pos)
            except (AttributeError, OSError):
                pass  # stream not seekable; OOM protection may be unavailable
        while True:
            key = read_string(stream)
            # separator
            if len(key) == 0:
                break
            res.read_value(stream, key, version=version)
        del res._prescan_vout
        return res


class OutputScope(PSBTScope):
    def __init__(self, unknown: dict = {}, vout=None, compress=CompressMode.KEEP_ALL):
        self.compress = compress
        self.value = None
        self.script_pubkey = None
        if vout is not None:
            self.value = vout.value
            self.script_pubkey = vout.script_pubkey
        self.unknown = unknown
        self.redeem_script = None
        self.witness_script = None
        self.bip32_derivations = OrderedDict()
        self.taproot_bip32_derivations = OrderedDict()
        self.taproot_internal_key = None
        self.parse_unknowns()

    def clear_metadata(self, compress=CompressMode.CLEAR_ALL):
        """Removes metadata like derivations, utxos etc except final or partial sigs"""
        if compress == CompressMode.KEEP_ALL:
            return
        self.unknown = {}
        self.redeem_script = None
        self.witness_script = None
        self.bip32_derivations = OrderedDict()
        self.taproot_bip32_derivations = OrderedDict()
        self.taproot_internal_key = None

    def update(self, other):
        self.value = other.value if other.value is not None else self.value
        self.script_pubkey = other.script_pubkey or self.script_pubkey
        self.unknown.update(other.unknown)
        self.redeem_script = other.redeem_script or self.redeem_script
        self.witness_script = other.witness_script or self.witness_script
        self.bip32_derivations.update(other.bip32_derivations)
        self.taproot_bip32_derivations.update(other.taproot_bip32_derivations)
        self.taproot_internal_key = other.taproot_internal_key

    @property
    def vout(self):
        return TransactionOutput(self.value, self.script_pubkey)

    def read_value(self, stream, k, version=None):
        # separator
        if len(k) == 0:
            return

        v = read_string(stream)

        # redeem script
        if k[0] == 0x00:
            if len(k) != 1:
                raise PSBTError("Invalid redeem script key")
            elif self.redeem_script is None:
                self.redeem_script = Script(v)
            else:
                raise PSBTError("Duplicated redeem script")
        # witness script
        elif k[0] == 0x01:
            if len(k) != 1:
                raise PSBTError("Invalid witness script key")
            elif self.witness_script is None:
                self.witness_script = Script(v)
            else:
                raise PSBTError("Duplicated witness script")
        # bip32 derivation
        elif k[0] == 0x02:
            pub = ec.PublicKey.parse(k[1:])
            if pub in self.bip32_derivations:
                raise PSBTError("Duplicated derivation path")
            else:
                self.bip32_derivations[pub] = DerivationPath.parse(v)

        # PSBTv2 fields
        elif k == b"\x03":
            if version != 2:
                raise PSBTError("PSBT_OUT_AMOUNT not allowed in PSBTv0")
            if len(v) != 8:
                raise PSBTError("PSBT_OUT_AMOUNT must be 8 bytes")
            if self.value is not None:
                raise PSBTError("Duplicated PSBT_OUT_AMOUNT")
            self.value = _signed_from_bytes(v)
        elif k == b"\x04":
            if version != 2:
                raise PSBTError("PSBT_OUT_SCRIPT not allowed in PSBTv0")
            if self.script_pubkey is not None:
                raise PSBTError("Duplicated PSBT_OUT_SCRIPT")
            self.script_pubkey = Script(v)

        # PSBT_OUT_TAP_INTERNAL_KEY
        elif k[0] == 0x05:
            self.taproot_internal_key = ec.PublicKey.from_xonly(v)

        # PSBT_OUT_TAP_BIP32_DERIVATION
        elif k[0] == 0x07:
            pub = ec.PublicKey.from_xonly(k[1:])
            if pub not in self.taproot_bip32_derivations:
                b = BytesIO(v)
                num_leaf_hashes = compact.read_from(b)
                leaf_hashes = [b.read(32) for i in range(num_leaf_hashes)]
                if not all([len(leaf) == 32 for leaf in leaf_hashes]):
                    raise PSBTError("Invalid length of taproot leaf hashes")
                der = DerivationPath.read_from(b)
                self.taproot_bip32_derivations[pub] = (leaf_hashes, der)

        else:
            if k in self.unknown:
                raise PSBTError("Duplicated key")
            self.unknown[k] = v

    def write_to(self, stream, skip_separator=False, version=None, **kwargs) -> int:
        r = 0
        if self.redeem_script is not None:
            r += stream.write(b"\x01\x00")
            r += self.redeem_script.write_to(stream)  # script serialization has length
        if self.witness_script is not None:
            r += stream.write(b"\x01\x01")
            r += self.witness_script.write_to(stream)  # script serialization has length
        for pub in self.bip32_derivations:
            r += ser_string(stream, b"\x02" + pub.serialize())
            r += ser_string(stream, self.bip32_derivations[pub].serialize())

        if version == 2:
            if self.value is not None:
                r += ser_string(stream, b"\x03")
                # BIP370: PSBT_OUT_AMOUNT is a signed 64-bit integer
                r += ser_string(stream, _signed_to_bytes(self.value, 8))
            if self.script_pubkey is not None:
                r += ser_string(stream, b"\x04")
                r += self.script_pubkey.write_to(stream)

        # PSBT_OUT_TAP_INTERNAL_KEY
        if self.taproot_internal_key is not None:
            r += ser_string(stream, b"\x05")
            r += ser_string(stream, self.taproot_internal_key.xonly())

        # PSBT_OUT_TAP_BIP32_DERIVATION
        for pub in self.taproot_bip32_derivations:
            r += ser_string(stream, b"\x07" + pub.xonly())
            leaf_hashes, derivation = self.taproot_bip32_derivations[pub]
            r += ser_string(
                stream,
                compact.to_bytes(len(leaf_hashes))
                + b"".join(leaf_hashes)
                + derivation.serialize(),
            )

        # unknown
        for key in self.unknown:
            r += ser_string(stream, key)
            r += ser_string(stream, self.unknown[key])
        # separator
        if not skip_separator:
            r += stream.write(b"\x00")
        return r

    @classmethod
    def read_from(cls, stream, compress=CompressMode.KEEP_ALL, vout=None, version=None):
        res = cls({}, vout=vout, compress=compress)
        while True:
            key = read_string(stream)
            # separator
            if len(key) == 0:
                break
            res.read_value(stream, key, version=version)
        return res


class TxModifiable:
    INPUTS = 0b00000001
    OUTPUTS = 0b00000010
    SIGHASH_SINGLE = 0b00000100


class PSBT(EmbitBase):
    MAGIC = b"psbt\xff"
    # for subclasses
    PSBTIN_CLS = InputScope
    PSBTOUT_CLS = OutputScope
    TX_CLS = Transaction

    @classmethod
    def _validate_v2_output(cls, out, i):
        """Check that a PSBTv2 output has all required fields.
        Subclasses (e.g. PSET) may override this to accept alternative fields."""
        if out.value is None:
            raise PSBTError(
                "PSBTv2 output %d missing required PSBT_OUT_AMOUNT (0x03)" % i
            )
        if out.script_pubkey is None:
            raise PSBTError(
                "PSBTv2 output %d missing required PSBT_OUT_SCRIPT (0x04)" % i
            )

    def __init__(self, tx=None, unknown=None, version=None):
        self.version = version  # None for v0, 2 for v2
        self.inputs = []
        self.outputs = []
        self.tx_version = None
        self.locktime = None
        self.tx_modifiable_flags = None
        self._raw_input_count_from_global = None
        self._raw_output_count_from_global = None

        if tx is not None:
            self.parse_tx(tx)

        self.unknown = {} if unknown is None else unknown
        self.xpubs = OrderedDict()
        self.parse_unknowns()

    def parse_tx(self, tx):
        self.tx_version = tx.version
        self.locktime = tx.locktime
        self.inputs = [self.PSBTIN_CLS(vin=vin) for vin in tx.vin]
        self.outputs = [self.PSBTOUT_CLS(vout=vout) for vout in tx.vout]

    @staticmethod
    def _classify_locktimes(inputs):
        """Classify inputs by locktime requirement type.

        Returns a tuple of (height_locktimes, time_locktimes, inputs_with_requirements)
        where the lists contain the respective locktime values and the count is the
        number of inputs that express at least one locktime requirement.
        """
        height_locktimes = []
        time_locktimes = []
        inputs_with_requirements = 0
        for inp in inputs:
            has_requirement = False
            if inp.required_height_locktime is not None:
                height_locktimes.append(inp.required_height_locktime)
                has_requirement = True
            if inp.required_time_locktime is not None:
                time_locktimes.append(inp.required_time_locktime)
                has_requirement = True
            if has_requirement:
                inputs_with_requirements += 1
        return height_locktimes, time_locktimes, inputs_with_requirements

    def determine_locktime(self):
        """
        Determines the appropriate locktime according to PSBTv2 rules.
        Returns the locktime that should be used for the transaction.
        """
        if self.version != 2:
            return self.locktime or 0

        height_locktimes, time_locktimes, inputs_with_locktime_requirements = (
            self._classify_locktimes(self.inputs)
        )

        # If no inputs have locktime requirements, use fallback
        if inputs_with_locktime_requirements == 0:
            return self.locktime or 0

        # height preferred, if ALL inputs with requirements support it
        if len(height_locktimes) == inputs_with_locktime_requirements:
            return max(height_locktimes)

        # fall back to time if ALL inputs with requirements support it
        if len(time_locktimes) == inputs_with_locktime_requirements:
            return max(time_locktimes)

        raise PSBTError(
            "Cannot determine locktime: inputs have conflicting height and time locktime requirements"
        )

    def _validate_locktime_compatibility(self, inputs):
        """Verify that the given input list has mutually compatible locktime requirements.

        Raises PSBTError when no single locktime type (height or time) is supported
        by every input that expresses a requirement.
        """
        height_locktimes, time_locktimes, inputs_with_requirements = (
            self._classify_locktimes(inputs)
        )
        if inputs_with_requirements == 0:
            return
        if (
            len(height_locktimes) == inputs_with_requirements
            or len(time_locktimes) == inputs_with_requirements
        ):
            return
        raise PSBTError(
            "Input locktime requirements are incompatible with existing inputs"
        )

    @property
    def tx(self):
        if self.version == 2:
            locktime = self.determine_locktime()
        else:
            locktime = self.locktime or 0

        if self.version == 2 and self.tx_version is None:
            raise PSBTError("PSBTv2 is missing required PSBT_GLOBAL_TX_VERSION")
        tx_version = self.tx_version if self.tx_version is not None else 2
        return self.TX_CLS(
            version=tx_version,
            locktime=locktime,
            vin=[inp.vin for inp in self.inputs],
            vout=[out.vout for out in self.outputs],
        )

    def sighash_segwit(self, *args, **kwargs):
        return self.tx.sighash_segwit(*args, **kwargs)

    def sighash_legacy(self, *args, **kwargs):
        return self.tx.sighash_legacy(*args, **kwargs)

    def sighash_taproot(self, *args, **kwargs):
        return self.tx.sighash_taproot(*args, **kwargs)

    @property
    def is_verified(self):
        return all([inp.is_verified for inp in self.inputs])

    def verify(self, ignore_missing=False):
        for i, inp in enumerate(self.inputs):
            inp.verify(ignore_missing)
        return self.is_verified

    def utxo(self, i):
        if self.inputs[i].is_verified:
            return self.inputs[i].utxo
        if not (self.inputs[i].witness_utxo or self.inputs[i].non_witness_utxo):
            raise PSBTError("Missing previous utxo on input %d" % i)
        return (
            self.inputs[i].witness_utxo
            or self.inputs[i].non_witness_utxo.vout[self.inputs[i].vout]
        )

    def fee(self):
        fee = sum([self.utxo(i).value for i in range(len(self.inputs))])
        fee -= sum([out.value for out in self.tx.vout])
        return fee

    def write_to(self, stream) -> int:
        # magic bytes
        r = stream.write(self.MAGIC)
        if self.version != 2:
            # unsigned tx flag
            r += stream.write(b"\x01\x00")
            # write serialized tx
            tx = self.tx.serialize()
            r += ser_string(stream, tx)
        # xpubs
        for xpub in self.xpubs:
            r += ser_string(stream, b"\x01" + xpub.serialize())
            r += ser_string(stream, self.xpubs[xpub].serialize())

        if self.version == 2:
            if self.tx_version is None:
                raise PSBTError(
                    "Cannot serialize PSBTv2: missing required PSBT_GLOBAL_TX_VERSION"
                )
            r += ser_string(stream, b"\x02")
            # BIP370: PSBT_GLOBAL_TX_VERSION is a signed int32
            r += ser_string(stream, _signed_to_bytes(self.tx_version, 4))
            if self.locktime is not None:
                r += ser_string(stream, b"\x03")
                r += ser_string(stream, self.locktime.to_bytes(4, "little"))
            r += ser_string(stream, b"\x04")
            r += ser_string(stream, compact.to_bytes(len(self.inputs)))
            r += ser_string(stream, b"\x05")
            r += ser_string(stream, compact.to_bytes(len(self.outputs)))
            if self.tx_modifiable_flags is not None:
                r += ser_string(stream, b"\x06")
                r += ser_string(stream, bytes([self.tx_modifiable_flags]))
            r += ser_string(stream, b"\xfb")
            r += ser_string(stream, self.version.to_bytes(4, "little"))
        # unknown
        for key in self.unknown:
            r += ser_string(stream, key)
            r += ser_string(stream, self.unknown[key])
        # separator
        r += stream.write(b"\x00")
        # inputs
        for inp in self.inputs:
            r += inp.write_to(stream, version=self.version)
        # outputs
        for out in self.outputs:
            r += out.write_to(stream, version=self.version)
        return r

    @classmethod
    def from_base64(cls, b64, compress=CompressMode.KEEP_ALL):
        raw = a2b_base64(b64)
        return cls.parse(raw, compress=compress)

    def to_base64(self):
        return b2a_base64(self.serialize()).strip().decode()

    def to_string(self, encoding="base64"):
        if encoding == "base64":
            return self.to_base64()
        else:
            return hexlify(self.serialize()).decode()

    @classmethod
    def from_string(cls, s, compress=CompressMode.KEEP_ALL):
        if s.startswith(hexlify(cls.MAGIC).decode()):
            return cls.parse(unhexlify(s), compress=compress)
        else:
            return cls.from_base64(s, compress=compress)

    @classmethod
    def read_from(cls, stream, compress=CompressMode.KEEP_ALL):
        """
        Compress flag allows to load and verify non_witness_utxo
        without storing them in memory and save the utxo internally for signing.
        This helps against out-of-memory errors.
        """
        if stream.read(len(cls.MAGIC)) != cls.MAGIC:
            raise PSBTError("Invalid PSBT magic")

        global_kvs = OrderedDict()
        while True:
            key = read_string(stream)
            if len(key) == 0:  # Separator
                break
            value = read_string(stream)
            if key in global_kvs:
                raise PSBTError(
                    "Duplicated global key: %s" % hexlify(key).decode()
                )
            global_kvs[key] = value

        # Determine PSBT version from PSBT_GLOBAL_VERSION (0xfb)
        version = None
        if b"\xfb" in global_kvs:
            if len(global_kvs[b"\xfb"]) != 4:
                raise PSBTError("PSBT_GLOBAL_VERSION must be 4 bytes")
            parsed_version = int.from_bytes(global_kvs[b"\xfb"], "little")
            if parsed_version == 2:
                version = 2
            elif parsed_version == 0:
                version = (
                    None  # explicit PSBT_GLOBAL_VERSION=0 is valid for v0 per BIP174
                )
            else:
                raise PSBTError(
                    "Unsupported PSBT_GLOBAL_VERSION value: %d" % parsed_version
                )

        if version == 2:  # PSBTv2
            if b"\x00" in global_kvs:  # PSBT_GLOBAL_UNSIGNED_TX
                raise PSBTError("PSBT_GLOBAL_UNSIGNED_TX is not allowed in PSBTv2")
            # Pass all global KVs to unknown; __init__ calls parse_unknowns.
            psbt = cls(tx=None, unknown=global_kvs, version=version)

            # Validate that input/output counts were processed by parse_unknowns
            if psbt._raw_input_count_from_global is None:
                raise PSBTError(
                    "PSBTv2 missing or invalid PSBT_GLOBAL_INPUT_COUNT (0x04)"
                )
            if psbt._raw_output_count_from_global is None:
                raise PSBTError(
                    "PSBTv2 missing or invalid PSBT_GLOBAL_OUTPUT_COUNT (0x05)"
                )
            if psbt.tx_version is None:
                raise PSBTError("PSBTv2 missing required PSBT_GLOBAL_TX_VERSION (0x02)")
        else:  # PSBTv0 (version is None or 0)
            if b"\x00" not in global_kvs:
                raise PSBTError("PSBT_GLOBAL_UNSIGNED_TX (0x00) is required for PSBTv0")

            # Check for forbidden v2-only global keys in v0 context.
            # PSBT_GLOBAL_VERSION (0xfb) with value 0 is explicitly permitted by BIP174
            # and was already validated above, so it is excluded from this set.
            v2_only_global_keys = {b"\x02", b"\x03", b"\x04", b"\x05", b"\x06"}
            for k_v2_only in v2_only_global_keys:
                if k_v2_only in global_kvs:
                    raise PSBTError(
                        "Global key %s is not allowed in PSBTv0"
                        % hexlify(k_v2_only).decode()
                    )

            tx_bytes = global_kvs.pop(b"\x00")  # Remove so it's not in unknown
            tx_for_v0 = cls.TX_CLS.parse(tx_bytes)
            psbt = cls(tx=tx_for_v0, unknown=global_kvs, version=version)

        if version == 2:
            num_inputs = psbt._raw_input_count_from_global
            num_outputs = psbt._raw_output_count_from_global

            parsed_inputs = []
            for _ in range(num_inputs):
                parsed_inputs.append(
                    cls.PSBTIN_CLS.read_from(
                        stream,
                        compress=compress,
                        vin=None,
                        version=version,
                    )
                )
            psbt.inputs = parsed_inputs

            for i, inp in enumerate(psbt.inputs):
                if inp.txid is None:
                    raise PSBTError(
                        "PSBTv2 input %d missing required "
                        "PSBT_IN_PREVIOUS_TXID (0x0e)" % i
                    )
                if inp.vout is None:
                    raise PSBTError(
                        "PSBTv2 input %d missing required "
                        "PSBT_IN_OUTPUT_INDEX (0x0f)" % i
                    )

            parsed_outputs = []
            for _ in range(num_outputs):
                parsed_outputs.append(
                    cls.PSBTOUT_CLS.read_from(
                        stream,
                        compress=compress,
                        vout=None,
                        version=version,
                    )
                )
            psbt.outputs = parsed_outputs

            for i, out in enumerate(psbt.outputs):
                cls._validate_v2_output(out, i)
        else:
            temp_inputs = []
            for i in range(len(psbt.inputs)):
                temp_inputs.append(
                    cls.PSBTIN_CLS.read_from(
                        stream,
                        compress=compress,
                        vin=psbt.inputs[i].vin,
                        version=version,
                    )
                )
            psbt.inputs = temp_inputs

            temp_outputs = []
            for i in range(len(psbt.outputs)):
                temp_outputs.append(
                    cls.PSBTOUT_CLS.read_from(
                        stream,
                        compress=compress,
                        vout=psbt.outputs[i].vout,
                        version=version,
                    )
                )
            psbt.outputs = temp_outputs

        return psbt

    def parse_unknowns(self):
        # Handle PSBT_GLOBAL_VERSION first
        if b"\xfb" in self.unknown:
            self.unknown.pop(b"\xfb", None)

        if b"\x06" in self.unknown:
            flags_bytes = self.unknown.pop(b"\x06")
            if len(flags_bytes) != 1:
                raise PSBTError("PSBT_GLOBAL_TX_MODIFIABLE must be 1 byte")
            self.tx_modifiable_flags = flags_bytes[0]

        for k in list(self.unknown):
            # xpub field
            if k[0] == 0x01:
                xpub = bip32.HDKey.parse(k[1:])
                self.xpubs[xpub] = DerivationPath.parse(self.unknown.pop(k))
            elif k == b"\x02":
                if self.version == 2:
                    v = self.unknown.pop(k)
                    if len(v) != 4:
                        raise PSBTError("PSBT_GLOBAL_TX_VERSION must be 4 bytes")
                    # BIP370: PSBT_GLOBAL_TX_VERSION is a signed int32
                    self.tx_version = _signed_from_bytes(v)
            elif k == b"\x03":
                if self.version == 2:
                    v = self.unknown.pop(k)
                    if len(v) != 4:
                        raise PSBTError("PSBT_GLOBAL_FALLBACK_LOCKTIME must be 4 bytes")
                    self.locktime = int.from_bytes(v, "little")
            elif k == b"\x04":
                if self.version == 2:
                    if self._raw_input_count_from_global is not None:
                        self.unknown.pop(k, None)
                        continue
                    self._raw_input_count_from_global = compact.from_bytes(
                        self.unknown.pop(k)
                    )
                    # Store count only; do not pre-allocate objects to avoid
                    # attacker-controlled memory exhaustion.
            elif k == b"\x05":
                if self.version == 2:
                    if self._raw_output_count_from_global is not None:
                        self.unknown.pop(k, None)
                        continue
                    self._raw_output_count_from_global = compact.from_bytes(
                        self.unknown.pop(k)
                    )
                    # Store count only; do not pre-allocate objects to avoid
                    # attacker-controlled memory exhaustion.

    def sighash(self, i, sighash=SIGHASH.ALL, **kwargs):
        inp = self.inputs[i]

        if inp.is_taproot:
            values = [inp.utxo.value for inp in self.inputs]
            scripts = [inp.utxo.script_pubkey for inp in self.inputs]
            return self.sighash_taproot(
                i,
                script_pubkeys=scripts,
                values=values,
                sighash=sighash,
                **kwargs,
            )

        value = inp.utxo.value
        sc = inp.witness_script or inp.redeem_script or inp.utxo.script_pubkey

        # detect if it is a segwit input
        is_segwit = (
            inp.witness_script
            or inp.witness_utxo
            or inp.utxo.script_pubkey.script_type() in {"p2wpkh", "p2wsh"}
            or (
                inp.redeem_script
                and inp.redeem_script.script_type() in {"p2wpkh", "p2wsh"}
            )
        )
        # convert to p2pkh according to bip143
        if sc.script_type() == "p2wpkh":
            sc = script.p2pkh_from_p2wpkh(sc)

        if is_segwit:
            h = self.sighash_segwit(i, sc, value, sighash=sighash)
        else:
            h = self.sighash_legacy(i, sc, sighash=sighash)
        return h

    def sign_input_with_tapkey(
        self,
        key: ec.PrivateKey,
        input_index: int,
        inp=None,
        sighash=SIGHASH.DEFAULT,
    ) -> int:
        """Sign taproot input with key. Signs with internal or leaf key."""
        # get input ourselves if not provided
        inp = inp or self.inputs[input_index]
        if not inp.is_taproot:
            return 0
        # check if key is internal key
        pk = key.taproot_tweak(inp.taproot_merkle_root or b"")
        if pk.xonly() in inp.utxo.script_pubkey.data:
            h = self.sighash(
                input_index,
                sighash=sighash,
            )
            sig = pk.schnorr_sign(h)
            sigdata = sig.serialize()
            if sighash != SIGHASH.DEFAULT:
                sigdata += bytes([sighash])
            inp.taproot_key_sig = sigdata
            inp.final_scriptwitness = Witness([sigdata])
            # no need to sign anything else
            return 1
        counter = 0
        # negate if necessary
        pub = ec.PublicKey.from_xonly(key.xonly())
        # iterate over leafs and sign
        for ctrl, sc in inp.taproot_scripts.items():
            if pub.xonly() not in sc:
                continue
            leaf_version = sc[-1]
            script = Script(sc[:-1])
            h = self.sighash(
                input_index,
                sighash=sighash,
                ext_flag=1,
                script=script,
                leaf_version=leaf_version,
            )
            sig = key.schnorr_sign(h)
            leaf = hashes.tagged_hash(
                "TapLeaf", bytes([leaf_version]) + script.serialize()
            )
            sigdata = sig.serialize()
            # append sighash if necessary
            if sighash != SIGHASH.DEFAULT:
                sigdata += bytes([sighash])
            inp.taproot_sigs[(pub, leaf)] = sigdata
            counter += 1
        return counter

    def sign_with(self, root, sighash=SIGHASH.DEFAULT) -> int:
        """
        Signs psbt with root key (HDKey or similar).
        Returns number of signatures added to PSBT.
        Sighash kwarg is set to SIGHASH.DEFAULT,
        for segwit and legacy it's replaced to SIGHASH.ALL
        so if PSBT is asking to sign with a different sighash this function won't sign.
        If you want to sign with sighashes provided in the PSBT - set sighash=None.
        """
        counter = 0  # sigs counter
        # check if it's a descriptor, and sign with all private keys in this descriptor
        if hasattr(root, "keys"):
            for k in root.keys:
                if hasattr(k, "is_private") and k.is_private:
                    counter += self.sign_with(k, sighash)
            return counter

        # if WIF - fingerprint is None
        fingerprint = None
        # if descriptor key
        if hasattr(root, "origin"):
            if not root.is_private:  # pubkey can't sign
                return 0
            if root.is_extended:  # use fingerprint only for HDKey
                fingerprint = root.fingerprint
            else:
                root = root.key  # WIF key
        # if HDKey
        if not fingerprint and hasattr(root, "my_fingerprint"):
            fingerprint = root.my_fingerprint

        rootpub = root.get_public_key()
        sec = rootpub.sec()
        pkh = hashes.hash160(sec)

        counter = 0
        for i, inp in enumerate(self.inputs):
            # SIGHASH.DEFAULT is only for taproot, fallback
            # to SIGHASH.ALL for other inputs
            required_sighash = sighash
            if not inp.is_taproot and required_sighash == SIGHASH.DEFAULT:
                required_sighash = SIGHASH.ALL

            # check which sighash to use
            inp_sighash = inp.sighash_type
            if inp_sighash is None:
                inp_sighash = required_sighash or SIGHASH.DEFAULT
            if not inp.is_taproot and inp_sighash == SIGHASH.DEFAULT:
                inp_sighash = SIGHASH.ALL

            # if input sighash is set and is different from required sighash
            # we don't sign this input
            # except DEFAULT is functionally the same as ALL
            if required_sighash is not None and inp_sighash != required_sighash:
                if inp_sighash not in {
                    SIGHASH.DEFAULT,
                    SIGHASH.ALL,
                } or required_sighash not in {SIGHASH.DEFAULT, SIGHASH.ALL}:
                    continue

            # get all possible derivations with matching fingerprint
            bip32_derivations = OrderedDict()  # OrderedDict to keep order
            if fingerprint:
                # if taproot derivations are present add them
                for pub in inp.taproot_bip32_derivations:
                    _leafs, derivation = inp.taproot_bip32_derivations[pub]
                    if derivation.fingerprint == fingerprint:
                        # Add only if not already present
                        if (pub, derivation) not in bip32_derivations:
                            bip32_derivations[(pub, derivation)] = True

                # segwit and legacy derivations
                for pub in inp.bip32_derivations:
                    derivation = inp.bip32_derivations[pub]
                    if derivation.fingerprint == fingerprint:
                        if (pub, derivation) not in bip32_derivations:
                            bip32_derivations[(pub, derivation)] = True

            # get derived keys for signing
            derived_keypairs = OrderedDict()  # (prv, pub)
            for pub, derivation in bip32_derivations:
                der = derivation.derivation
                # descriptor key has origin derivation that we take into account
                if hasattr(root, "origin"):
                    if root.origin:
                        if root.origin.derivation != der[: len(root.origin.derivation)]:
                            # derivation doesn't match - go to next input
                            continue
                        der = der[len(root.origin.derivation) :]
                    hdkey = root.key.derive(der)
                else:
                    hdkey = root.derive(der)

                if hdkey.xonly() != pub.xonly():
                    raise PSBTError("Derivation path doesn't look right")
                # Insert into derived_keypairs if not present
                if (hdkey.key, pub) not in derived_keypairs:
                    derived_keypairs[(hdkey.key, pub)] = True

            # sign with taproot key
            if inp.is_taproot:
                # try to sign with individual private key (WIF)
                # or with root without derivations
                tap_sigs = self.sign_input_with_tapkey(
                    root,
                    i,
                    inp,
                    sighash=inp_sighash,
                )
                # sign with all derived keys
                for prv, pub in derived_keypairs:
                    tap_sigs += self.sign_input_with_tapkey(
                        prv,
                        i,
                        inp,
                        sighash=inp_sighash,
                    )
                if tap_sigs > 0:
                    counter += tap_sigs
                    self._update_tx_modifiable(inp_sighash)
                continue

            # hash can be reused
            h = self.sighash(i, sighash=inp_sighash)
            sc = inp.witness_script or inp.redeem_script or inp.utxo.script_pubkey

            # check if root itself is included in the script
            if sec in sc.data or pkh in sc.data:
                sig = root.sign(h)
                inp.partial_sigs[rootpub] = sig.serialize() + bytes([inp_sighash])
                counter += 1
                self._update_tx_modifiable(inp_sighash)

            for prv, pub in derived_keypairs:
                sig = prv.sign(h)
                inp.partial_sigs[pub] = sig.serialize() + bytes([inp_sighash])
                counter += 1
                self._update_tx_modifiable(inp_sighash)

        return counter

    def _update_tx_modifiable(self, inp_sighash: int) -> None:
        """
        Update PSBT_GLOBAL_TX_MODIFIABLE after a signature is added.
        BIP-370 Signer role: signer must update this field to reflect
        the constraints imposed by the sighash type used.
        """
        if self.version != 2:
            return

        is_anyonecanpay = bool(inp_sighash & SIGHASH.ANYONECANPAY)
        sighash_type = inp_sighash & 0x1F

        if self.tx_modifiable_flags is None:
            self.tx_modifiable_flags = 0

        if not is_anyonecanpay:
            self.tx_modifiable_flags &= ~TxModifiable.INPUTS
        if sighash_type != SIGHASH.NONE:
            self.tx_modifiable_flags &= ~TxModifiable.OUTPUTS
        if sighash_type == SIGHASH.SINGLE:
            self.tx_modifiable_flags |= TxModifiable.SIGHASH_SINGLE

    def get_tx_modifiable(self):
        return self.tx_modifiable_flags

    def set_tx_modifiable(self, flags):
        if self.version != 2:
            raise PSBTError("GLOBAL_TX_MODIFIABLE only supported in PSBTv2")
        self.tx_modifiable_flags = flags

    def is_inputs_modifiable(self):
        if self.version != 2:
            return True
        if self.tx_modifiable_flags is None:
            return False
        return bool(self.tx_modifiable_flags & TxModifiable.INPUTS)

    def is_outputs_modifiable(self):
        if self.version != 2:
            return True
        if self.tx_modifiable_flags is None:
            return False
        return bool(self.tx_modifiable_flags & TxModifiable.OUTPUTS)

    def has_sighash_single(self):
        if self.version != 2 or self.tx_modifiable_flags is None:
            return False
        return bool(self.tx_modifiable_flags & TxModifiable.SIGHASH_SINGLE)

    @classmethod
    def create_v2(cls, tx_version=2, fallback_locktime=None, tx_modifiable=None):
        """Creator role convenience factory: initialise an empty PSBTv2.

        BIP-370 Creator role: set PSBT_GLOBAL_VERSION=2, PSBT_GLOBAL_TX_VERSION,
        and optionally PSBT_GLOBAL_FALLBACK_LOCKTIME and PSBT_GLOBAL_TX_MODIFIABLE
        so the Constructor role can immediately begin adding inputs and outputs.
        """
        if tx_modifiable is None:
            tx_modifiable = TxModifiable.INPUTS | TxModifiable.OUTPUTS
        psbt = cls(tx=None, version=2)
        psbt.tx_version = tx_version
        psbt.locktime = fallback_locktime
        psbt.tx_modifiable_flags = tx_modifiable
        return psbt

    def add_input(self, input_scope):
        if not self.is_inputs_modifiable():
            raise PSBTError("Inputs are not modifiable")
        if self.version == 2:
            # BIP370 Constructor role: validate required fields
            if input_scope.txid is None:
                raise PSBTError("PSBTv2 input must have PSBT_IN_PREVIOUS_TXID")
            if input_scope.vout is None:
                raise PSBTError("PSBTv2 input must have PSBT_IN_OUTPUT_INDEX")
            # Validate locktime compatibility before mutating state
            if (
                input_scope.required_height_locktime is not None
                or input_scope.required_time_locktime is not None
            ):
                self._validate_locktime_compatibility(self.inputs + [input_scope])
            # BIP370: when SIGHASH_SINGLE signatures are present the input/output
            # pairing must be preserved. This append-only API only adds to the end,
            # which never reindexes existing pairs, so the addition is always safe.
        self.inputs.append(input_scope)
        if self.version == 2:
            self._raw_input_count_from_global = len(self.inputs)

    def add_output(self, output_scope):
        if not self.is_outputs_modifiable():
            raise PSBTError("Outputs are not modifiable")
        if self.version == 2:
            # BIP370 Constructor role: validate required fields
            if output_scope.value is None:
                raise PSBTError("PSBTv2 output must have PSBT_OUT_AMOUNT")
            if output_scope.script_pubkey is None:
                raise PSBTError("PSBTv2 output must have PSBT_OUT_SCRIPT")
        self.outputs.append(output_scope)
        if self.version == 2:
            self._raw_output_count_from_global = len(self.outputs)
