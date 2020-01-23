# ref: https://github.com/bitcoin-core/HWI/blob/master/hwilib/serializations.py

from .transaction import Transaction, TransactionOutput, _parse
from . import compact
from . import bip32
from . import ec
from .script import Script
from . import script

def ser_string(s):
    return compact.to_bytes(len(s))+s

def read_string(stream):
    l = compact.read_from(stream)
    s = stream.read(l)
    if len(s)!=l:
        raise ValueError("Failed to read %d bytes" % l)
    return s

class PSBT:
    def __init__(self, tx=None):
        if tx is not None:
            self.tx = tx
        else:
            self.tx = Transaction()
        self.inputs = []
        self.outputs = []
        self.unknown = {}
        self.xpubs = {}

    def serialize(self):
        # magic bytes
        r = b"psbt\xff"
        # unsigned tx flag
        r += b"\x01\x00"
        # write serialized tx
        tx = self.tx.serialize()
        r += ser_string(tx)
        # xpubs
        for xpub in self.xpubs:
            r += ser_string(b'\x01'+xpub.serialize())
            r += ser_string(self.xpubs[xpub].serialize())
        # unknown
        for key in self.unknown:
            r += ser_string(key)
            r += ser_string(self.unknown[key])
        # separator
        r += b"\x00"
        # inputs
        for inp in self.inputs:
            r += inp.serialize()
        # outputs
        for out in self.outputs:
            r += out.serialize()
        return r

    @classmethod
    def parse(cls, b):
        return _parse(cls, b)

    @classmethod
    def read_from(cls, stream):
        tx = None
        unknown = {}
        xpubs = {}
        # check magic
        if(stream.read(5)!=b'psbt\xff'):
            raise ValueError("Invalid PSBT")
        while True:
            key = read_string(stream)
            # separator
            if len(key) == 0:
                break
            value = read_string(stream)
            # tx
            if key == b'\x00':
                if tx is None:
                    tx = Transaction.parse(value)
                else:
                    raise ValueError("Failed to parse PSBT - duplicated transaction field")
            else:
                if key in unknown:
                    raise ValueError("Duplicated key")
                unknown[key] = value
        
        psbt = cls(tx)
        # now we can go through all the key-values and parse them
        for k in list(unknown.keys()):
            # xpub field
            if k[0] == 0x01:
                xpub = bip32.HDKey.parse(k[1:])
                xpubs[xpub] = DerivationPath.parse(unknown.pop(k))
        psbt.unknown = unknown
        psbt.xpubs = xpubs
        # input scopes
        for i in range(len(tx.vin)):
            psbt.inputs.append(InputScope.read_from(stream))
        # output scopes
        for i in range(len(tx.vout)):
            psbt.outputs.append(OutputScope.read_from(stream))
        return psbt

    def sign_with(self, root):
        fingerprint = root.child(0).fingerprint
        for i, inp in enumerate(self.inputs):
            for pub in inp.bip32_derivations:
                # check if it is root key
                if inp.bip32_derivations[pub].fingerprint == fingerprint:
                    hdkey = root.derive(inp.bip32_derivations[pub].derivation)
                    mypub = hdkey.key.get_public_key()
                    if mypub != pub:
                        raise ValueError("Derivation path doesn't look right")
                    sig = None
                    if inp.non_witness_utxo is not None:
                        # legacy
                        # sc = inp.non_witness_utxo
                        raise NotImplementedError("Legacy signing is not implemented")
                    elif inp.witness_utxo is not None:
                        # segwit
                        value = inp.witness_utxo.value
                        sc = inp.witness_utxo.script_pubkey
                        if inp.redeem_script is not None:
                            sc = inp.redeem_script
                        if inp.witness_script is not None:
                            sc = inp.witness_script
                        if sc.script_type() == "p2wpkh":
                            sc = script.p2pkh_from_p2wpkh(sc)
                        h = self.tx.sighash_segwit(i, sc, value)
                        sig = hdkey.key.sign(h)
                    if sig is not None:
                        # sig plus sighash_all
                        inp.partial_sigs[mypub] = sig.serialize()+b"\x01"

class DerivationPath:
    def __init__(self, fingerprint, derivation):
        self.fingerprint = fingerprint
        self.derivation = derivation

    def serialize(self):
        r = b''
        r += self.fingerprint
        for idx in self.derivation:
            r += idx.to_bytes(4, 'little')
        return r

    @classmethod
    def parse(cls, b):
        return _parse(cls, b)

    @classmethod
    def read_from(cls, stream):
        fingerprint = stream.read(4)
        derivation = []
        while True:
            r = stream.read(4)
            if len(r) == 0:
                break
            if len(r) < 4:
                raise ValueError("Invalid length")
            derivation.append(int.from_bytes(r, 'little'))
        return cls(fingerprint, derivation)

class PSBTScope:
    def __init__(self, unknown={}):
        self.unknown = unknown

    def serialize(self):
        # unknown
        r = b''
        for key in self.unknown:
            r += ser_string(key)
            r += ser_string(self.unknown[key])
        # separator
        r += b'\x00'
        return r

    @classmethod
    def parse(cls, b):
        return _parse(cls, b)

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
                raise ValueError("Duplicated key")
            unknown[key] = value
        # now we can go through all the key-values and parse them
        return cls(unknown)

class InputScope(PSBTScope):
    def __init__(self, unknown={}):
        self.unknown = unknown
        self.non_witness_utxo = None
        self.witness_utxo = None
        self.partial_sigs = {}
        self.sighash_type = None
        self.redeem_script = None
        self.witness_script = None
        self.bip32_derivations = {}
        self.parse_unknowns()

    def parse_unknowns(self):
        # go through all the unknowns and parse them
        for k in list(self.unknown.keys()):
            # legacy utxo
            if k == b'\x00':
                if self.non_witness_utxo is not None or self.witness_utxo is not None:
                    raise ValueError("Duplicated utxo value")
                else:
                    self.non_witness_utxo = Transaction.parse(self.unknown.pop(k))
            elif k == b'\x01':
                if self.non_witness_utxo is not None or self.witness_utxo is not None:
                    raise ValueError("Duplicated utxo value")
                else:
                    self.witness_utxo = TransactionOutput.parse(self.unknown.pop(k))
            elif k[0] == 0x02:
                pub = ec.PublicKey.parse(k[1:])
                if pub in self.partial_sigs:
                    raise ValueError("Duplicated partial sig")
                else:
                    self.partial_sigs[pub] = self.unknown.pop(k)
            elif k == b'\x03':
                if self.sighash_type is None:
                    if len(self.unknown[k])!=4:
                        raise ValueError("Sighash type should be 4 bytes long")
                    self.sighash_type = int.from_bytes(self.unknown.pop(k), 'big')
                else:
                    raise ValueError("Duplicated sighash type")
            elif k == b'\x04':
                if self.redeem_script is None:
                    self.redeem_script = Script(self.unknown.pop(k))
                else:
                    raise ValueError("Duplicated redeem script")
            elif k == b'\x05':
                if self.witness_script is None:
                    self.witness_script = Script(self.unknown.pop(k))
                else:
                    raise ValueError("Duplicated witness script")
            elif k[0] == 0x06:
                pub = ec.PublicKey.parse(k[1:])
                if pub in self.bip32_derivations:
                    raise ValueError("Duplicated derivation path")
                else:
                    self.bip32_derivations[pub] = DerivationPath.parse(self.unknown.pop(k))
            # keys 0x07 (PSBT_IN_FINAL_SCRIPTSIG)
            #      0x08 (PSBT_IN_FINAL_SCRIPTWITNESS),
            #      0x09 (PSBT_IN_POR_COMMITMENT)
            # are not implemented yet

    def serialize(self):
        r = b''
        if self.non_witness_utxo is not None:
            r += b'\x01\x00'
            r += ser_string(self.non_witness_utxo.serialize())
        if self.witness_utxo is not None:
            r += b'\x01\x01'
            r += ser_string(self.witness_utxo.serialize())
        for pub in self.partial_sigs:
            r += ser_string(b'\x02'+pub.serialize())
            r += ser_string(self.partial_sigs[pub])
        if self.sighash_type is not None:
            r += b'\x01\x03'
            r += ser_string(self.sighash_type.to_bytes(4, 'big'))
        if self.redeem_script is not None:
            r += b'\x01\x04'
            r += self.redeem_script.serialize() # script serialization has length
        if self.witness_script is not None:
            r += b'\x01\x05'
            r += self.witness_script.serialize() # script serialization has length
        for pub in self.bip32_derivations:
            r += ser_string(b'\x06'+pub.serialize())
            r += ser_string(self.bip32_derivations[pub].serialize())
        # unknown
        for key in self.unknown:
            r += ser_string(key)
            r += ser_string(self.unknown[key])
        # separator
        r += b'\x00'
        return r

class OutputScope(PSBTScope):
    def __init__(self, unknown={}):
        self.unknown = unknown
        self.redeem_script = None
        self.witness_script = None
        self.bip32_derivations = {}
        self.parse_unknowns()

    def parse_unknowns(self):
        # go through all the unknowns and parse them
        for k in list(self.unknown.keys()):
            if k == b'\x00':
                if self.redeem_script is None:
                    self.redeem_script = Script(self.unknown.pop(k))
                else:
                    raise ValueError("Duplicated redeem script")
            elif k == b'\x01':
                if self.witness_script is None:
                    self.witness_script = Script(self.unknown.pop(k))
                else:
                    raise ValueError("Duplicated witness script")
            elif k[0] == 0x02:
                pub = ec.PublicKey.parse(k[1:])
                if pub in self.bip32_derivations:
                    raise ValueError("Duplicated derivation path")
                else:
                    self.bip32_derivations[pub] = DerivationPath.parse(self.unknown.pop(k))

    def serialize(self):
        r = b''
        if self.redeem_script is not None:
            r += b'\x01\x00'
            r += self.redeem_script.serialize() # script serialization has length
        if self.witness_script is not None:
            r += b'\x01\x01'
            r += self.witness_script.serialize() # script serialization has length
        for pub in self.bip32_derivations:
            r += ser_string(b'\x02'+pub.serialize())
            r += ser_string(self.bip32_derivations[pub].serialize())
        # unknown
        for key in self.unknown:
            r += ser_string(key)
            r += ser_string(self.unknown[key])
        # separator
        r += b'\x00'
        return r