# ref: https://github.com/bitcoin-core/HWI/blob/master/hwilib/serializations.py

from collections import OrderedDict

from .transaction import Transaction, TransactionOutput
from . import compact
from . import bip32
from . import ec
from .script import Script, Witness
from . import script
from .base import EmbitBase, EmbitError
from binascii import b2a_base64, a2b_base64, hexlify


class PSBTError(EmbitError):
    pass


def ser_string(stream, s: bytes) -> int:
    return stream.write(compact.to_bytes(len(s))) + stream.write(s)


def read_string(stream) -> bytes:
    l = compact.read_from(stream)
    s = stream.read(l)
    if len(s) != l:
        raise PSBTError("Failed to read %d bytes" % l)
    return s


class PSBT(EmbitBase):
    MAGIC = b"psbt\xff"

    def __init__(self, tx=None):
        if tx is not None:
            self.tx = tx
            self.inputs = [InputScope() for i in range(len(tx.vin))]
            self.outputs = [OutputScope() for i in range(len(tx.vout))]
        else:
            self.tx = Transaction()
            self.inputs = []
            self.outputs = []
        self.unknown = {}
        self.xpubs = OrderedDict()

    def write_to(self, stream) -> int:
        # magic bytes
        r = stream.write(self.MAGIC)
        # unsigned tx flag
        r += stream.write(b"\x01\x00")
        # write serialized tx
        tx = self.tx.serialize()
        r += ser_string(stream, tx)
        # xpubs
        for xpub in self.xpubs:
            r += ser_string(stream, b"\x01" + xpub.serialize())
            r += ser_string(stream, self.xpubs[xpub].serialize())
        # unknown
        for key in self.unknown:
            r += ser_string(stream, key)
            r += ser_string(stream, self.unknown[key])
        # separator
        r += stream.write(b"\x00")
        # inputs
        for inp in self.inputs:
            r += inp.write_to(stream)
        # outputs
        for out in self.outputs:
            r += out.write_to(stream)
        return r

    @classmethod
    def from_base64(cls, b64):
        raw = a2b_base64(b64)
        return cls.parse(raw)

    def to_base64(self):
        return b2a_base64(self.serialize()).strip().decode()

    def to_string(self, encoding="base64"):
        if encoding == "base64":
            return self.to_base64()
        else:
            return hexlify(self.serialize()).decode()

    @classmethod
    def from_string(cls, s):
        if s.startswith("70736274ff"):
            return cls.parse(unhexlify(s))
        else:
            return cls.from_base64(s)

    @classmethod
    def read_from(cls, stream):
        tx = None
        unknown = {}
        xpubs = OrderedDict()
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
                    tx = Transaction.parse(value)
                else:
                    raise PSBTError(
                        "Failed to parse PSBT - duplicated transaction field"
                    )
            else:
                if key in unknown:
                    raise PSBTError("Duplicated key")
                unknown[key] = value

        psbt = cls(tx)
        # now we can go through all the key-values and parse them
        for k in list(unknown):
            # xpub field
            if k[0] == 0x01:
                xpub = bip32.HDKey.parse(k[1:])
                xpubs[xpub] = DerivationPath.parse(unknown.pop(k))
        psbt.unknown = unknown
        psbt.xpubs = xpubs
        # input scopes
        for i in range(len(tx.vin)):
            psbt.inputs[i] = InputScope.read_from(stream)
        # output scopes
        for i in range(len(tx.vout)):
            psbt.outputs[i] = OutputScope.read_from(stream)
        return psbt

    def sign_with(self, root) -> int:
        """
        Signs psbt with root key (HDKey or similar).
        Returns number of signatures added to PSBT
        """
        fingerprint = root.child(0).fingerprint
        counter = 0
        for i, inp in enumerate(self.inputs):
            for pub in inp.bip32_derivations:
                # check if it is root key
                if inp.bip32_derivations[pub].fingerprint == fingerprint:
                    hdkey = root.derive(inp.bip32_derivations[pub].derivation)
                    mypub = hdkey.key.get_public_key()
                    if mypub != pub:
                        raise PSBTError("Derivation path doesn't look right")
                    sig = None
                    utxo = None
                    if inp.non_witness_utxo is not None:
                        if inp.non_witness_utxo.txid() != self.tx.vin[i].txid:
                            raise PSBTError("Invalid utxo")
                        utxo = inp.non_witness_utxo.vout[self.tx.vin[i].vout]
                    elif inp.witness_utxo is not None:
                        utxo = inp.witness_utxo
                    else:
                        raise PSBTError("We need at least one utxo field")
                    value = utxo.value
                    sc = utxo.script_pubkey
                    if inp.redeem_script is not None:
                        sc = inp.redeem_script
                    if inp.witness_script is not None:
                        sc = inp.witness_script
                    if sc.script_type() == "p2wpkh":
                        sc = script.p2pkh_from_p2wpkh(sc)
                    # detect if it is a segwit input
                    # tx.input[i] doesn't have any info about that in raw psbt
                    if (
                        inp.witness_script is not None
                        or inp.witness_utxo is not None
                        or utxo.script_pubkey.script_type() in {"p2wpkh", "p2wsh"}
                        or (
                            inp.redeem_script is not None
                            and inp.redeem_script.script_type() in {"p2wpkh", "p2wsh"}
                        )
                    ):
                        h = self.tx.sighash_segwit(i, sc, value)
                    else:
                        h = self.tx.sighash_legacy(i, sc)
                    sig = hdkey.key.sign(h)
                    counter += 1
                    if sig is not None:
                        # sig plus sighash_all
                        inp.partial_sigs[mypub] = sig.serialize() + b"\x01"
        return counter


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

    def write_to(self, stream) -> int:
        # unknown
        r = 0
        for key in self.unknown:
            r += ser_string(stream, key)
            r += ser_string(stream, self.unknown[key])
        # separator
        r += stream.write(b"\x00")
        return r

    @classmethod
    def read_from(cls, stream):
        unknown = {}
        while True:
            key = read_string(stream)
            # separator
            if len(key) == 0:
                break
            value = read_string(stream)
            if key in unknown:
                raise PSBTError("Duplicated key")
            unknown[key] = value
        # now we can go through all the key-values and parse them
        return cls(unknown)


class InputScope(PSBTScope):
    def __init__(self, unknown: dict = {}):
        self.unknown = unknown
        self.non_witness_utxo = None
        self.witness_utxo = None
        self.partial_sigs = OrderedDict()
        self.sighash_type = None
        self.redeem_script = None
        self.witness_script = None
        self.bip32_derivations = OrderedDict()
        self.final_scriptsig = None
        self.final_scriptwitness = None
        self.parse_unknowns()

    def parse_unknowns(self):
        # go through all the unknowns and parse them
        for k in list(self.unknown):
            # legacy utxo
            if k[0] == 0x00:
                if len(k) != 1:
                    raise PSBTError("Invalid non-witness utxo key")
                elif self.non_witness_utxo is not None:
                    raise PSBTError("Duplicated utxo value")
                else:
                    self.non_witness_utxo = Transaction.parse(self.unknown.pop(k))
            # witness utxo
            elif k[0] == 0x01:
                if len(k) != 1:
                    raise PSBTError("Invalid witness utxo key")
                elif self.witness_utxo is not None:
                    raise PSBTError("Duplicated utxo value")
                else:
                    self.witness_utxo = TransactionOutput.parse(self.unknown.pop(k))
            # partial signature
            elif k[0] == 0x02:
                pub = ec.PublicKey.parse(k[1:])
                if pub in self.partial_sigs:
                    raise PSBTError("Duplicated partial sig")
                else:
                    self.partial_sigs[pub] = self.unknown.pop(k)
            # hash type
            elif k[0] == 0x03:
                if len(k) != 1:
                    raise PSBTError("Invalid sighash type key")
                elif self.sighash_type is None:
                    if len(self.unknown[k]) != 4:
                        raise PSBTError("Sighash type should be 4 bytes long")
                    self.sighash_type = int.from_bytes(self.unknown.pop(k), "big")
                else:
                    raise PSBTError("Duplicated sighash type")
            # redeem script
            elif k[0] == 0x04:
                if len(k) != 1:
                    raise PSBTError("Invalid redeem script key")
                elif self.redeem_script is None:
                    self.redeem_script = Script(self.unknown.pop(k))
                else:
                    raise PSBTError("Duplicated redeem script")
            # witness script
            elif k[0] == 0x05:
                if len(k) != 1:
                    raise PSBTError("Invalid witness script key")
                elif self.witness_script is None:
                    self.witness_script = Script(self.unknown.pop(k))
                else:
                    raise PSBTError("Duplicated witness script")
            # bip32 derivation
            elif k[0] == 0x06:
                pub = ec.PublicKey.parse(k[1:])
                if pub in self.bip32_derivations:
                    raise PSBTError("Duplicated derivation path")
                else:
                    self.bip32_derivations[pub] = DerivationPath.parse(
                        self.unknown.pop(k)
                    )
            # final scriptsig
            elif k[0] == 0x07:
                if len(k) != 1:
                    raise PSBTError("Invalid final scriptsig key")
                elif self.final_scriptsig is None:
                    self.final_scriptsig = Script(self.unknown.pop(k))
                else:
                    raise PSBTError("Duplicated final scriptsig")
            # final script witness
            elif k[0] == 0x08:
                if len(k) != 1:
                    raise PSBTError("Invalid final scriptwitness key")
                elif self.final_scriptwitness is None:
                    self.final_scriptwitness = Witness.parse(self.unknown.pop(k))
                else:
                    raise PSBTError("Duplicated final scriptwitness")

    def write_to(self, stream) -> int:
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
            r += ser_string(stream, self.sighash_type.to_bytes(4, "big"))
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
        # unknown
        for key in self.unknown:
            r += ser_string(stream, key)
            r += ser_string(stream, self.unknown[key])
        # separator
        r += stream.write(b"\x00")
        return r


class OutputScope(PSBTScope):
    def __init__(self, unknown: dict = {}):
        self.unknown = unknown
        self.redeem_script = None
        self.witness_script = None
        self.bip32_derivations = OrderedDict()
        self.parse_unknowns()

    def parse_unknowns(self):
        # go through all the unknowns and parse them
        for k in list(self.unknown):
            # redeem script
            if k[0] == 0x00:
                if len(k) != 1:
                    raise PSBTError("Invalid redeem script key")
                elif self.redeem_script is None:
                    self.redeem_script = Script(self.unknown.pop(k))
                else:
                    raise PSBTError("Duplicated redeem script")
            # witness script
            elif k[0] == 0x01:
                if len(k) != 1:
                    raise PSBTError("Invalid witness script key")
                elif self.witness_script is None:
                    self.witness_script = Script(self.unknown.pop(k))
                else:
                    raise PSBTError("Duplicated witness script")
            # bip32 derivation
            elif k[0] == 0x02:
                pub = ec.PublicKey.parse(k[1:])
                if pub in self.bip32_derivations:
                    raise PSBTError("Duplicated derivation path")
                else:
                    self.bip32_derivations[pub] = DerivationPath.parse(
                        self.unknown.pop(k)
                    )

    def write_to(self, stream) -> int:
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
        # unknown
        for key in self.unknown:
            r += ser_string(stream, key)
            r += ser_string(stream, self.unknown[key])
        # separator
        r += stream.write(b"\x00")
        return r
