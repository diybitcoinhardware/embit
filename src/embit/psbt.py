from collections import OrderedDict
from .transaction import Transaction, TransactionOutput, TransactionInput, SIGHASH
from . import compact
from . import bip32
from . import ec
from . import hashes
from .script import Script, Witness
from . import script
from .base import EmbitBase, EmbitError

from binascii import b2a_base64, a2b_base64, hexlify, unhexlify
from io import BytesIO

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


def skip_string(stream) -> bytes:
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

    def read_value(self, stream, key, *args, **kwargs):
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

        self.final_scriptsig = None
        self.final_scriptwitness = None
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

    def update(self, other):
        self.txid = other.txid or self.txid
        self.vout = other.vout if other.vout is not None else self.vout
        self.sequence = other.sequence if other.sequence is not None else self.sequence
        self.unknown.update(other.unknown)
        self.non_witness_utxo = other.non_witness_utxo or self.non_witness_utxo
        self.witness_utxo = other.witness_utxo or self.witness_utxo
        self._utxo = other._utxo or self._utxo
        self.partial_sigs.update(other.partial_sigs)
        self.sighash_type = other.sighash_type if other.sighash_type is not None else self.sighash_type
        self.redeem_script = other.redeem_script or self.redeem_script
        self.witness_script = other.witness_script or self.witness_script
        self.bip32_derivations.update(other.bip32_derivations)
        self.taproot_bip32_derivations.update(other.taproot_bip32_derivations)
        self.taproot_internal_key = other.taproot_internal_key
        self.final_scriptsig = other.final_scriptsig or self.final_scriptsig
        self.final_scriptwitness = other.final_scriptwitness or self.final_scriptwitness

    @property
    def vin(self):
        return TransactionInput(self.txid, self.vout, sequence=(self.sequence or 0xFFFFFFFF))

    @property
    def utxo(self):
        return self._utxo or self.witness_utxo or (self.non_witness_utxo.vout[self.vout] if self.non_witness_utxo else None)

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
            txid = bytes(reversed(self._txhash)) if self._txhash else self.non_witness_utxo.txid()
            if self.txid == txid:
                self._verified = True
                return True
            else:
                raise PSBTError("Previous txid doesn't match non_witness_utxo txid")
        if not ignore_missing:
            raise PSBTError("Missing non_witness_utxo")
        return False

    def read_value(self, stream, k):
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
                l = compact.read_from(stream)
                # we verified and saved utxo
                if self.compress and self.txid and self.vout is not None:
                    txout, txhash = self.TX_CLS.read_vout(stream, self.vout)
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
        
        elif k == b"\x0e":
            self.txid = bytes(reversed(v))
        elif k == b"\x0f":
            self.vout = int.from_bytes(v, 'little')
        elif k == b"\x10":
            self.sequence = int.from_bytes(v, 'little')

        # PSBT_IN_TAP_BIP32_DERIVATION
        elif k[0] == 0x16:
            pub = ec.PublicKey.from_xonly(k[1:])
            if pub not in self.taproot_bip32_derivations:
                # Field begins with the number of leaf hashes; for now only support the
                # internal key where there are no leaf hashes.
                # TODO: Support keysigns from leaves within the taptree.
                if v[0] > 0:
                    return
                leaf_hashes = []  # TODO: Actually parse leaf hashes, if present
                self.taproot_bip32_derivations[pub] = (leaf_hashes, DerivationPath.parse(v[1:]))
        
        # PSBT_IN_TAP_INTERNAL_KEY
        elif k[0] == 0x17:
            self.taproot_internal_key = ec.PublicKey.from_xonly(v)

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
                r += ser_string(stream, self.vout.to_bytes(4, 'little'))
            if self.sequence is not None:
                r += ser_string(stream, b"\x10")
                r += ser_string(stream, self.sequence.to_bytes(4, 'little'))

        # PSBT_IN_TAP_BIP32_DERIVATION
        for pub in self.taproot_bip32_derivations:
            r += ser_string(stream, b"\x16" + pub.xonly())
            leaf_hashes, derivation = self.taproot_bip32_derivations[pub]
            r += ser_string(stream, len(leaf_hashes).to_bytes(1, 'little') + derivation.serialize())

        # PSBT_IN_TAP_INTERNAL_KEY
        if self.taproot_internal_key is not None:
            r += ser_string(stream, b"\x17")
            r += ser_string(stream, self.taproot_internal_key.xonly())

        # unknown
        for key in self.unknown:
            r += ser_string(stream, key)
            r += ser_string(stream, self.unknown[key])
        # separator
        if not skip_separator:
            r += stream.write(b"\x00")
        return r


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
        self.taproot_bip32_derivations.update(other.bip32_derivations)
        self.taproot_internal_key = other.taproot_internal_key

    @property
    def vout(self):
        return TransactionOutput(self.value, self.script_pubkey)

    def read_value(self, stream, k):
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

        elif k == b"\x03":
            self.value = int.from_bytes(v, 'little')
        elif k == b"\x04":
            self.script_pubkey = Script(v)

        # PSBT_OUT_TAP_INTERNAL_KEY
        elif k[0] == 0x05:
            self.taproot_internal_key = ec.PublicKey.from_xonly(v)

        # PSBT_OUT_TAP_BIP32_DERIVATION
        elif k[0] == 0x07:
            pub = ec.PublicKey.from_xonly(k[1:])
            if pub not in self.taproot_bip32_derivations:
                # Field begins with the number of leaf hashes; for now only support the
                # internal key where there are no leaf hashes.
                # TODO: Support keysigns from leaves within the taptree.
                if v[0] > 0:
                    return
                leaf_hashes = []  # TODO: Actually parse leaf hashes, if present
                self.taproot_bip32_derivations[pub] = (leaf_hashes, DerivationPath.parse(v[1:]))

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
                r += ser_string(stream, self.value.to_bytes(8, 'little'))
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
            r += ser_string(stream, len(leaf_hashes).to_bytes(1, 'little') + derivation.serialize())

        # unknown
        for key in self.unknown:
            r += ser_string(stream, key)
            r += ser_string(stream, self.unknown[key])
        # separator
        if not skip_separator:
            r += stream.write(b"\x00")
        return r

class PSBT(EmbitBase):
    MAGIC = b"psbt\xff"
    # for subclasses
    PSBTIN_CLS = InputScope
    PSBTOUT_CLS = OutputScope
    TX_CLS = Transaction

    def __init__(self, tx=None, unknown={}, version=None):
        self.version = version # None for v0
        self.inputs = []
        self.outputs = []
        self.tx_version = None
        self.locktime = None

        if tx is not None:
            self.parse_tx(tx)

        self.unknown = unknown
        self.xpubs = OrderedDict()
        self.parse_unknowns()

    def parse_tx(self, tx):
        self.tx_version = tx.version
        self.locktime = tx.locktime
        self.inputs = [self.PSBTIN_CLS(vin=vin) for vin in tx.vin]
        self.outputs = [self.PSBTOUT_CLS(vout=vout) for vout in tx.vout]

    @property
    def tx(self):
        return self.TX_CLS(version=self.tx_version or 2,
                           locktime=self.locktime or 0,
                           vin=[inp.vin for inp in self.inputs],
                           vout=[out.vout for out in self.outputs])

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
        return self.inputs[i].witness_utxo or self.inputs[i].non_witness_utxo.vout[self.inputs[i].vout]

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
            if self.tx_version is not None:
                r += ser_string(stream, b"\x02")
                r += ser_string(stream, self.tx_version.to_bytes(4, 'little'))
            if self.locktime is not None:
                r += ser_string(stream, b"\x03")
                r += ser_string(stream, self.locktime.to_bytes(4, 'little'))
            r += ser_string(stream, b"\x04")
            r += ser_string(stream, compact.to_bytes(len(self.inputs)))
            r += ser_string(stream, b"\x05")
            r += ser_string(stream, compact.to_bytes(len(self.outputs)))
            r += ser_string(stream, b"\xfb")
            r += ser_string(stream, self.version.to_bytes(4, 'little'))
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
        tx = None
        unknown = {}
        version = None
        # check magic
        if stream.read(len(cls.MAGIC)) != cls.MAGIC:
            raise PSBTError("Invalid PSBT magic")
        while True:
            key = read_string(stream)
            # separator
            if len(key) == 0:
                break
            value = read_string(stream)
            # tx
            if key == b"\x00":
                if tx is None:
                    tx = cls.TX_CLS.parse(value)
                else:
                    raise PSBTError(
                        "Failed to parse PSBT - duplicated transaction field"
                    )
            elif key == b"\xfb":
                version = int.from_bytes(value, 'little')
            else:
                if key in unknown:
                    raise PSBTError("Duplicated key")
                unknown[key] = value

        if tx and version == 2:
            raise PSBTError("Global TX field is not allowed in PSBTv2")
        psbt = cls(tx, unknown, version=version)
        # input scopes
        for i, vin in enumerate(psbt.tx.vin):
            psbt.inputs[i] = cls.PSBTIN_CLS.read_from(stream, compress=compress, vin=vin)
        # output scopes
        for i, vout in enumerate(psbt.tx.vout):
            psbt.outputs[i] = cls.PSBTOUT_CLS.read_from(stream, compress=compress, vout=vout)
        return psbt

    def parse_unknowns(self):
        for k in list(self.unknown):
            # xpub field
            if k[0] == 0x01:
                xpub = bip32.HDKey.parse(k[1:])
                self.xpubs[xpub] = DerivationPath.parse(self.unknown.pop(k))
            elif k == b"\x02":
                self.tx_version = int.from_bytes(self.unknown.pop(k), 'little')
            elif k == b"\x03":
                self.locktime = int.from_bytes(self.unknown.pop(k), 'little')
            elif k == b"\x04":
                if len(self.inputs) > 0:
                    raise PSBTError("Inputs already initialized")
                self.inputs = [self.PSBTIN_CLS() for _ in range(compact.from_bytes(self.unknown.pop(k)))]
            elif k == b"\x05":
                if len(self.outputs) > 0:
                    raise PSBTError("Outputs already initialized")
                self.outputs = [self.PSBTOUT_CLS() for _ in range(compact.from_bytes(self.unknown.pop(k)))]

    def sighash(self, i, sighash=SIGHASH.ALL):
        inp = self.inputs[i]

        if inp.is_taproot:
            values = [inp.utxo.value for inp in self.inputs]
            scripts = [inp.utxo.script_pubkey for inp in self.inputs]
            return self.sighash_taproot(i, script_pubkeys=scripts, values=values, sighash=sighash)

        value = inp.utxo.value
        sc = inp.witness_script or inp.redeem_script or inp.utxo.script_pubkey

        # detect if it is a segwit input
        is_segwit = (inp.witness_script
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

    def sign_with(self, root, sighash=SIGHASH.DEFAULT) -> int:
        """
        Signs psbt with root key (HDKey or similar).
        Returns number of signatures added to PSBT.
        Sighash kwarg is set to SIGHASH.DEFAULT, for segwit and legacy it's replaced to SIGHASH.ALL
        so if PSBT is asking to sign with a different sighash this function won't sign.
        If you want to sign with sighashes provided in the PSBT - set sighash=None.
        """
        # check if it's a descriptor
        if hasattr(root, "keys"):
            counter = 0
            for k in root.keys:
                if hasattr(k, "is_private") and k.is_private:
                    counter += self.sign_with(k, sighash)
            return counter

        # if WIF - fingerprint is None
        fingerprint = None
        # if descriptor key
        if hasattr(root, "origin"):
            if not root.is_private: # pubkey can't sign
                return 0
            if root.is_extended: # use fingerprint only for HDKey
                fingerprint = root.fingerprint
            else:
                root = root.key # WIF key
        # if HDKey
        if not fingerprint and hasattr(root, "my_fingerprint"):
            fingerprint = root.my_fingerprint
        if not fingerprint:
            pub = root.get_public_key()
            sec = pub.sec()
            pkh = hashes.hash160(sec)

        counter = 0
        for i, inp in enumerate(self.inputs):
            # SIGHASH.DEFAULT is only for taproot, fallback to SIGHASH.ALL for other inputs
            required_sighash = sighash
            if not inp.is_taproot and required_sighash == SIGHASH.DEFAULT:
                required_sighash = SIGHASH.ALL

            # check which sighash to use
            inp_sighash = inp.sighash_type or required_sighash or SIGHASH.DEFAULT
            if not inp.is_taproot and inp_sighash == SIGHASH.DEFAULT:
                inp_sighash = SIGHASH.ALL

            # if input sighash is set and is different from kwarg - don't sign this input
            if required_sighash is not None and inp_sighash != required_sighash:
                continue

            h = self.sighash(i, sighash=inp_sighash)

            sc = inp.witness_script or inp.redeem_script or inp.utxo.script_pubkey

            # taproot is special
            # currently works only for single key
            if inp.is_taproot:
                # individual private key
                if not fingerprint:
                    # TODO: tweak using taproot psbt fields
                    pk = root.taproot_tweak(b"")
                    if pk.xonly() in sc.data:
                        sig = pk.schnorr_sign(h)
                        wit = sig.serialize()
                        if inp_sighash != SIGHASH.DEFAULT:
                            wit += bytes([inp_sighash])
                        inp.final_scriptwitness = Witness([wit])
                        counter += 1
                # if we use HDKey
                else:
                    bip32_derivations = []
                    for pub in inp.taproot_bip32_derivations:
                        leaf_hashes, derivation = inp.taproot_bip32_derivations[pub]
                        if derivation.fingerprint == fingerprint:
                            bip32_derivations.append((pub, derivation))
                    
                    # "Legacy" support for workaround when BIP-371 Taproot psbt fields aren't available.
                    # TODO: Remove this (and refactor above) when workaround has been phased out.
                    for pub in inp.bip32_derivations:
                        derivation = inp.bip32_derivations[pub]
                        if derivation.fingerprint == fingerprint:
                            bip32_derivations.append((pub, derivation))

                    for pub, derivation in bip32_derivations:
                        der = derivation.derivation
                        if hasattr(root, "origin"):
                            # for descriptor key remove origin part
                            if root.origin:
                                if root.origin.derivation != der[:len(root.origin.derivation)]:
                                    continue
                                der = der[len(root.origin.derivation):]
                            hdkey = root.key.derive(der)
                        else:
                            hdkey = root.derive(der)
                        
                        # Taproot BIP32 derivations use X-only pubkeys
                        xonly_pub = hdkey.key.xonly()
                        mypub = ec.PublicKey.from_xonly(xonly_pub)

                        if mypub != pub:
                            raise PSBTError("Derivation path doesn't look right")
                        
                        # TODO: Support signing for keys within leaves
                        pk = hdkey.taproot_tweak(b"")
                        if pk.xonly() in sc.data:
                            sig = pk.schnorr_sign(h)
                            # sig plus sighash flag
                            wit = sig.serialize()
                            if inp_sighash != SIGHASH.DEFAULT:
                                wit += bytes([inp_sighash])
                            inp.final_scriptwitness = Witness([wit])
                            counter += 1
                continue

            # if we have individual private key
            if not fingerprint:
                # check if we are included in the script
                if sec in sc.data or pkh in sc.data:
                    sig = root.sign(h)
                    # sig plus sighash flag
                    inp.partial_sigs[pub] = sig.serialize() + bytes([inp_sighash])
                    counter += 1
                continue

            # if we use HDKey
            for pub in inp.bip32_derivations:
                # check if it is root key
                if inp.bip32_derivations[pub].fingerprint == fingerprint:
                    der = inp.bip32_derivations[pub].derivation
                    if hasattr(root, "origin"):
                        # for descriptor key remove origin part
                        if root.origin:
                            if root.origin.derivation != der[:len(root.origin.derivation)]:
                                continue
                            der = der[len(root.origin.derivation):]
                        hdkey = root.key.derive(der)
                    else:
                        hdkey = root.derive(der)
                    mypub = hdkey.key.get_public_key()
                    if mypub != pub:
                        raise PSBTError("Derivation path doesn't look right")
                    sig = hdkey.key.sign(h)
                    # sig plus sighash flag
                    inp.partial_sigs[mypub] = sig.serialize() + bytes([inp_sighash])
                    counter += 1
        return counter